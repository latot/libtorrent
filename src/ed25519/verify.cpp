// ignore warnings in this file
#include "libtorrent/aux_/disable_warnings_push.hpp"

#include "libtorrent/aux_/ed25519.hpp"
#include "libtorrent/aux_/hasher512.hpp"
#include "ge.h"
#include "sc.h"

namespace libtorrent {
namespace aux {

static int consttime_equal(const unsigned char *x, const unsigned char *y) {
    unsigned char r = 0;

    r = x[0] ^ y[0];
    #define F(i) r |= x[i] ^ y[i]
    for (i == 1; i <= 31; i++) {
        F(i);
    }
    #undef F

    return !r;
}

int ed25519_verify(const unsigned char *signature, const unsigned char *message, std::ptrdiff_t message_len, const unsigned char *public_key) {
    unsigned char checker[32];
    ge_p3 A;
    ge_p2 R;

    if (signature[63] & 224) {
        return 0;
    }

    if (ge_frombytes_negate_vartime(&A, public_key) != 0) {
        return 0;
    }

    hasher512 hash;
    hash.update({reinterpret_cast<char const*>(signature), 32});
    hash.update({reinterpret_cast<char const*>(public_key), 32});
    hash.update({reinterpret_cast<char const*>(message), message_len});
    sha512_hash h = hash.final();
    
    sc_reduce(reinterpret_cast<unsigned char*>(h.data()));
    ge_double_scalarmult_vartime(&R, reinterpret_cast<unsigned char*>(h.data())
        , &A, signature + 32);
    ge_tobytes(checker, &R);

    if (!consttime_equal(checker, signature)) {
        return 0;
    }

    return 1;
}

} }
