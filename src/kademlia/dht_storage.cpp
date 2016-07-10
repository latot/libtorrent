/*

Copyright (c) 2012-2016, Arvid Norberg, Alden Torres
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include "libtorrent/kademlia/dht_storage.hpp"

#include <tuple>
#include <algorithm>
#include <utility>
#include <map>
#include <set>
#include <string>

#include <libtorrent/socket_io.hpp>
#include <libtorrent/aux_/time.hpp>
#include <libtorrent/config.hpp>
#include <libtorrent/time.hpp>
#include <libtorrent/socket.hpp>
#include <libtorrent/sha1_hash.hpp>
#include <libtorrent/bloom_filter.hpp>
#include <libtorrent/address.hpp>
#include <libtorrent/session_settings.hpp>
#include <libtorrent/performance_counters.hpp>
#include <libtorrent/random.hpp>

#include <libtorrent/kademlia/item.hpp>
#include <libtorrent/kademlia/node_id.hpp>

namespace libtorrent {
namespace dht {
namespace
{
	using detail::write_endpoint;

	// this is the entry for every peer
	// the timestamp is there to make it possible
	// to remove stale peers
	struct peer_entry
	{
		time_point added;
		tcp::endpoint addr;
		bool seed;
	};

	// internal
	bool operator<(peer_entry const& lhs, peer_entry const& rhs)
	{
		return lhs.addr.address() == rhs.addr.address()
			? lhs.addr.port() < rhs.addr.port()
			: lhs.addr.address() < rhs.addr.address();
	}

	// this is a group. It contains a set of group members
	struct torrent_entry
	{
		std::string name;
		std::set<peer_entry> peers;
	};

#ifndef TORRENT_NO_DEPRECATE
	struct count_peers
	{
		int* count;
		count_peers(int* c): count(c) {}
		void operator()(std::pair<libtorrent::sha1_hash
			, torrent_entry> const& t)
		{
			*count += int(t.second.peers.size());
		}
	};
#endif

	// TODO: 2 make this configurable in dht_settings
	enum { announce_interval = 30 };

	struct dht_immutable_item
	{
		dht_immutable_item() : value(nullptr), num_announcers(0), size(0) {}
		// malloced space for the actual value
		char* value;
		// this counts the number of IPs we have seen
		// announcing this item, this is used to determine
		// popularity if we reach the limit of items to store
		bloom_filter<128> ips;
		// the last time we heard about this
		time_point last_seen;
		// number of IPs in the bloom filter
		int num_announcers;
		// size of malloced space pointed to by value
		int size;
	};

	struct ed25519_public_key { char bytes[item_pk_len]; };

	struct dht_mutable_item : dht_immutable_item
	{
		char sig[item_sig_len];
		std::int64_t seq;
		ed25519_public_key key;
		char* salt;
		int salt_size;
	};

	void touch_item(dht_immutable_item* f, address const& address)
	{
		f->last_seen = aux::time_now();

		// maybe increase num_announcers if we haven't seen this IP before
		sha1_hash iphash;
		hash_address(address, iphash);
		if (!f->ips.find(iphash))
		{
			f->ips.set(iphash);
			++f->num_announcers;
		}
	}

	// return true of the first argument is a better candidate for removal, i.e.
	// less important to keep
	struct immutable_item_comparator
	{
		immutable_item_comparator(std::vector<node_id> const& node_ids) : m_node_ids(node_ids) {}
		immutable_item_comparator(immutable_item_comparator const&) = default;

		bool operator() (std::pair<node_id, dht_immutable_item> const& lhs
			, std::pair<node_id, dht_immutable_item> const& rhs) const
		{
			int l_distance = min_distance_exp(lhs.first, m_node_ids);
			int r_distance = min_distance_exp(rhs.first, m_node_ids);

			// this is a score taking the popularity (number of announcers) and the
			// fit, in terms of distance from ideal storing node, into account.
			// each additional 5 announcers is worth one extra bit in the distance.
			// that is, an item with 10 announcers is allowed to be twice as far
			// from another item with 5 announcers, from our node ID. Twice as far
			// because it gets one more bit.
			return lhs.second.num_announcers / 5 - l_distance < rhs.second.num_announcers / 5 - r_distance;
		}

	private:

		// explicitly disallow assignment, to silence msvc warning
		immutable_item_comparator& operator=(immutable_item_comparator const&);

		std::vector<node_id> const& m_node_ids;
	};

	// picks the least important one (i.e. the one
	// the fewest peers are announcing, and farthest
	// from our node IDs)
	template<class Item>
	typename std::map<node_id, Item>::const_iterator pick_least_important_item(
		std::vector<node_id> const& node_ids, std::map<node_id, Item> const& table)
	{
		return std::min_element(table.begin()
			, table.end()
			, immutable_item_comparator(node_ids));
	}

	class dht_default_storage final : public dht_storage_interface, boost::noncopyable
	{
	typedef std::map<node_id, torrent_entry> table_t;
	typedef std::map<node_id, dht_immutable_item> dht_immutable_table_t;
	typedef std::map<node_id, dht_mutable_item> dht_mutable_table_t;

	public:

		dht_default_storage(dht_settings const& settings)
			: m_settings(settings)
		{
			m_counters.reset();
		}

		~dht_default_storage() override = default;

#ifndef TORRENT_NO_DEPRECATE
		size_t num_torrents() const override { return m_map.size(); }
		size_t num_peers() const override
		{
			int ret = 0;
			std::for_each(m_map.begin(), m_map.end(), count_peers(&ret));
			return ret;
		}
#endif
		void update_node_ids(std::vector<node_id> const& ids) override
		{
			m_node_ids = ids;
		}

		bool get_peers(sha1_hash const& info_hash
			, bool noseed, bool scrape
			, entry& peers) const override
		{
			table_t::const_iterator i = m_map.lower_bound(info_hash);
			if (i == m_map.end()) return false;
			if (i->first != info_hash) return false;

			torrent_entry const& v = i->second;

			if (!v.name.empty()) peers["n"] = v.name;

			if (scrape)
			{
				bloom_filter<256> downloaders;
				bloom_filter<256> seeds;

				for (std::set<peer_entry>::const_iterator peer_it = v.peers.begin()
					, end(v.peers.end()); peer_it != end; ++peer_it)
				{
					sha1_hash iphash;
					hash_address(peer_it->addr.address(), iphash);
					if (peer_it->seed) seeds.set(iphash);
					else downloaders.set(iphash);
				}

				peers["BFpe"] = downloaders.to_string();
				peers["BFsd"] = seeds.to_string();
			}
			else
			{
				int max = m_settings.max_peers_reply;
				// if these are IPv6 peers their addresses are 4x the size of IPv4
				// so reduce the max peers 4 fold to compensate
				// max_peers_reply should probably be specified in bytes
				if (!v.peers.empty() && v.peers.begin()->addr.protocol() == tcp::v6())
					max /= 4;
				int num = (std::min)(int(v.peers.size()), max);
				std::set<peer_entry>::const_iterator iter = v.peers.begin();
				entry::list_type& pe = peers["values"].list();
				std::string endpoint;

				for (int t = 0, m = 0; m < num && iter != v.peers.end(); ++iter, ++t)
				{
					if ((random() / float(UINT_MAX + 1.f)) * (num - t) >= num - m) continue;
					if (noseed && iter->seed) continue;
					endpoint.resize(18);
					std::string::iterator out = endpoint.begin();
					write_endpoint(iter->addr, out);
					endpoint.resize(out - endpoint.begin());
					pe.push_back(entry(endpoint));

					++m;
				}
			}
			return true;
		}

		void announce_peer(sha1_hash const& info_hash
			, tcp::endpoint const& endp
			, std::string const& name, bool seed) override
		{
			table_t::iterator ti = m_map.find(info_hash);
			torrent_entry* v;
			if (ti == m_map.end())
			{
				// we don't have this torrent, add it
				// do we need to remove another one first?
				if (!m_map.empty() && int(m_map.size()) >= m_settings.max_torrents)
				{
					// we need to remove some. Remove the ones with the
					// fewest peers
					int num_peers = int(m_map.begin()->second.peers.size());
					table_t::iterator candidate = m_map.begin();
					for (table_t::iterator i = m_map.begin()
						, end(m_map.end()); i != end; ++i)
					{
						if (int(i->second.peers.size()) > num_peers) continue;
						if (i->first == info_hash) continue;
						num_peers = int(i->second.peers.size());
						candidate = i;
					}
					m_map.erase(candidate);
					m_counters.peers -= num_peers;
					m_counters.torrents -= 1;
				}
				m_counters.torrents += 1;
				v = &m_map[info_hash];
			}
			else
			{
				v = &ti->second;
			}

			// the peer announces a torrent name, and we don't have a name
			// for this torrent. Store it.
			if (!name.empty() && v->name.empty())
			{
				std::string tname = name;
				if (tname.size() > 100) tname.resize(100);
				v->name = tname;
			}

			peer_entry peer;
			peer.addr = endp;
			peer.added = aux::time_now();
			peer.seed = seed;
			std::set<peer_entry>::iterator i = v->peers.find(peer);
			if (i != v->peers.end())
			{
				v->peers.erase(i++);
				m_counters.peers -= 1;
			}
			else if (v->peers.size() >= m_settings.max_peers)
			{
				// when we're at capacity, there's a 50/50 chance of dropping the
				// announcing peer or an existing peer
				if (random() & 1) return;
				i = v->peers.lower_bound(peer);
				if (i == v->peers.end()) --i;
				v->peers.erase(i++);
				m_counters.peers -= 1;
			}
			v->peers.insert(i, peer);
			m_counters.peers += 1;
		}

		bool get_immutable_item(sha1_hash const& target
			, entry& item) const override
		{
			dht_immutable_table_t::const_iterator i = m_immutable_table.find(target);
			if (i == m_immutable_table.end()) return false;

			item["v"] = bdecode(i->second.value, i->second.value + i->second.size);
			return true;
		}

		void put_immutable_item(sha1_hash const& target
			, char const* buf, int size
			, address const& addr) override
		{
			TORRENT_ASSERT(!m_node_ids.empty());
			dht_immutable_table_t::iterator i = m_immutable_table.find(target);
			if (i == m_immutable_table.end())
			{
				// make sure we don't add too many items
				if (int(m_immutable_table.size()) >= m_settings.max_dht_items)
				{
					auto j = pick_least_important_item(m_node_ids
						, m_immutable_table);

					TORRENT_ASSERT(j != m_immutable_table.end());
					free(j->second.value);
					m_immutable_table.erase(j);
					m_counters.immutable_data -= 1;
				}
				dht_immutable_item to_add;
				to_add.value = static_cast<char*>(malloc(size));
				to_add.size = size;
				memcpy(to_add.value, buf, size);

				std::tie(i, std::ignore) = m_immutable_table.insert(
					std::make_pair(target, to_add));
				m_counters.immutable_data += 1;
			}

//			std::fprintf(stderr, "added immutable item (%d)\n", int(m_immutable_table.size()));

			touch_item(&i->second, addr);
		}

		bool get_mutable_item_seq(sha1_hash const& target
			, std::int64_t& seq) const override
		{
			dht_mutable_table_t::const_iterator i = m_mutable_table.find(target);
			if (i == m_mutable_table.end()) return false;

			seq = i->second.seq;
			return true;
		}

		bool get_mutable_item(sha1_hash const& target
			, std::int64_t seq, bool force_fill
			, entry& item) const override
		{
			dht_mutable_table_t::const_iterator i = m_mutable_table.find(target);
			if (i == m_mutable_table.end()) return false;

			dht_mutable_item const& f = i->second;
			item["seq"] = f.seq;
			if (force_fill || (0 <= seq && seq < f.seq))
			{
				item["v"] = bdecode(f.value, f.value + f.size);
				item["sig"] = std::string(f.sig, f.sig + sizeof(f.sig));
				item["k"] = std::string(f.key.bytes, f.key.bytes + sizeof(f.key.bytes));
			}
			return true;
		}

		void put_mutable_item(sha1_hash const& target
			, char const* buf, int size
			, char const* sig
			, std::int64_t seq
			, char const* pk
			, char const* salt, int salt_size
			, address const& addr) override
		{
			TORRENT_ASSERT(!m_node_ids.empty());
			dht_mutable_table_t::iterator i = m_mutable_table.find(target);
			if (i == m_mutable_table.end())
			{
				// this is the case where we don't have an item in this slot
				// make sure we don't add too many items
				if (int(m_mutable_table.size()) >= m_settings.max_dht_items)
				{
					auto j = pick_least_important_item(m_node_ids
						, m_mutable_table);

					TORRENT_ASSERT(j != m_mutable_table.end());
					free(j->second.value);
					free(j->second.salt);
					m_mutable_table.erase(j);
					m_counters.mutable_data -= 1;
				}
				dht_mutable_item to_add;
				to_add.value = static_cast<char*>(malloc(size));
				to_add.size = size;
				to_add.seq = seq;
				to_add.salt = nullptr;
				to_add.salt_size = 0;
				if (salt_size > 0)
				{
					to_add.salt = static_cast<char*>(malloc(salt_size));
					to_add.salt_size = salt_size;
					memcpy(to_add.salt, salt, salt_size);
				}
				memcpy(to_add.sig, sig, sizeof(to_add.sig));
				memcpy(to_add.value, buf, size);
				memcpy(&to_add.key, pk, sizeof(to_add.key));

				std::tie(i, std::ignore) = m_mutable_table.insert(
					std::make_pair(target, to_add));
				m_counters.mutable_data += 1;
			}
			else
			{
				// this is the case where we already
				dht_mutable_item* item = &i->second;

				if (item->seq < seq)
				{
					if (item->size != size)
					{
						free(item->value);
						item->value = static_cast<char*>(malloc(size));
						item->size = size;
					}
					item->seq = seq;
					memcpy(item->sig, sig, sizeof(item->sig));
					memcpy(item->value, buf, size);
				}
			}

			touch_item(&i->second, addr);
		}

		void tick() override
		{
			time_point now(aux::time_now());

			// look through all peers and see if any have timed out
			for (table_t::iterator i = m_map.begin(), end(m_map.end()); i != end;)
			{
				torrent_entry& t = i->second;
				purge_peers(t.peers);

				if (!t.peers.empty())
				{
					++i;
					continue;
				}

				// if there are no more peers, remove the entry altogether
				m_map.erase(i++);
				m_counters.torrents -= 1;// peers is decreased by purge_peers
			}

			if (0 == m_settings.item_lifetime) return;

			time_duration lifetime = seconds(m_settings.item_lifetime);
			// item lifetime must >= 120 minutes.
			if (lifetime < minutes(120)) lifetime = minutes(120);

			for (dht_immutable_table_t::iterator i = m_immutable_table.begin();
				i != m_immutable_table.end();)
			{
				if (i->second.last_seen + lifetime > now)
				{
					++i;
					continue;
				}
				free(i->second.value);
				m_immutable_table.erase(i++);
				m_counters.immutable_data -= 1;
			}

			for (dht_mutable_table_t::iterator i = m_mutable_table.begin();
				i != m_mutable_table.end();)
			{
				if (i->second.last_seen + lifetime > now)
				{
					++i;
					continue;
				}
				free(i->second.value);
				free(i->second.salt);
				m_mutable_table.erase(i++);
				m_counters.mutable_data -= 1;
			}
		}

		dht_storage_counters counters() const override
		{
			return m_counters;
		}

	private:
		dht_settings const& m_settings;
		dht_storage_counters m_counters;

		std::vector<node_id> m_node_ids;
		table_t m_map;
		dht_immutable_table_t m_immutable_table;
		dht_mutable_table_t m_mutable_table;

		void purge_peers(std::set<peer_entry>& peers)
		{
			for (std::set<peer_entry>::iterator i = peers.begin()
				, end(peers.end()); i != end;)
			{
				// the peer has timed out
				if (i->added + minutes(int(announce_interval * 1.5f)) < aux::time_now())
				{
					peers.erase(i++);
					m_counters.peers -= 1;
				}
				else
					++i;
			}
		}
	};
}

void dht_storage_counters::reset()
{
	torrents = 0;
	peers = 0;
	immutable_data = 0;
	mutable_data = 0;
}

std::unique_ptr<dht_storage_interface> dht_default_storage_constructor(
	dht_settings const& settings)
{
	return std::unique_ptr<dht_default_storage>(new dht_default_storage(settings));
}

} } // namespace libtorrent::dht
