#include "m_rsa.hpp"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <memory>

// Helper to manage BIGNUM memory
struct BN_CTX_Deleter { void operator()(BN_CTX* ctx) const { BN_CTX_free(ctx); } };
struct BIGNUM_Deleter { void operator()(BIGNUM* bn) const { BN_clear_free(bn); } };

std::vector<uint8_t> MRSA::calculateEuler(BIGNUM* a, BIGNUM* b, BIGNUM* c, BN_CTX* ctx) {
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> p_minus_1(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> q_minus_1(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> r_minus_1(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> phi(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> temp(BN_new());

    // Calculate (a-1), (b-1), (c-1)
    BN_copy(p_minus_1.get(), a); BN_sub_word(p_minus_1.get(), 1);
    BN_copy(q_minus_1.get(), b); BN_sub_word(q_minus_1.get(), 1);
    BN_copy(r_minus_1.get(), c); BN_sub_word(r_minus_1.get(), 1);

    // phi(n) = (a-1)(b-1)(c-1)
    BN_mul(temp.get(), p_minus_1.get(), q_minus_1.get(), ctx);
    BN_mul(phi.get(), temp.get(), r_minus_1.get(), ctx);

    int numBytes = BN_num_bytes(phi.get());
    std::vector<uint8_t> phi_vec(numBytes);
    BN_bn2bin(phi.get(), phi_vec.data());
    
    return phi_vec;
}

TriplePrimeKey MRSA::generateKey(int keyLength) {
    std::unique_ptr<BN_CTX, BN_CTX_Deleter> ctx(BN_CTX_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> a(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> b(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> c(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> n(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> e(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> d(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> phi(BN_new());

    // 1. Generate 3 distinct primes. For a 1024-bit key, each is ~341 bits.
    int primeLength = keyLength / 3;
    BN_generate_prime_ex(a.get(), primeLength, 0, nullptr, nullptr, nullptr);
    BN_generate_prime_ex(b.get(), primeLength, 0, nullptr, nullptr, nullptr);
    BN_generate_prime_ex(c.get(), keyLength - (2 * primeLength), 0, nullptr, nullptr, nullptr);

    // 2. n = a * b * c
    BN_mul(n.get(), a.get(), b.get(), ctx.get());
    BN_mul(n.get(), n.get(), c.get(), ctx.get());

    // 3. phi(n) = (a-1)(b-1)(c-1)
    std::vector<uint8_t> phi_vec = calculateEuler(a.get(), b.get(), c.get(), ctx.get());
    BN_bin2bn(phi_vec.data(), phi_vec.size(), phi.get());

    // 4. Set public exponent e (commonly 65537)
    BN_set_word(e.get(), RSA_F4);

    // 5. Calculate private exponent d: e * d ≡ 1 (mod phi)
    BN_mod_inverse(d.get(), e.get(), phi.get(), ctx.get());

    TriplePrimeKey key;
    key.n.resize(BN_num_bytes(n.get())); BN_bn2bin(n.get(), key.n.data());
    key.e.resize(BN_num_bytes(e.get())); BN_bn2bin(e.get(), key.e.data());
    key.d.resize(BN_num_bytes(d.get())); BN_bn2bin(d.get(), key.d.data());
    key.p.resize(BN_num_bytes(a.get())); BN_bn2bin(a.get(), key.p.data());
    key.q.resize(BN_num_bytes(b.get())); BN_bn2bin(b.get(), key.q.data());
    key.r.resize(BN_num_bytes(c.get())); BN_bn2bin(c.get(), key.r.data());

    return key;
}

std::vector<uint8_t> MRSA::encrypt(const std::vector<uint8_t>& plaintext, 
                                   const std::vector<uint8_t>& n_vec, 
                                   const std::vector<uint8_t>& e_vec) {
    std::unique_ptr<BN_CTX, BN_CTX_Deleter> ctx(BN_CTX_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> m(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> e(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> n(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> c(BN_new());

    BN_bin2bn(plaintext.data(), plaintext.size(), m.get());
    BN_bin2bn(e_vec.data(), e_vec.size(), e.get());
    BN_bin2bn(n_vec.data(), n_vec.size(), n.get());

    BN_mod_exp(c.get(), m.get(), e.get(), n.get(), ctx.get());

    std::vector<uint8_t> ciphertext(BN_num_bytes(c.get()));
    BN_bn2bin(c.get(), ciphertext.data());
    return ciphertext;
}

std::vector<uint8_t> MRSA::decrypt(const std::vector<uint8_t>& ciphertext, 
                                   const TriplePrimeKey& privateKey) {
    std::unique_ptr<BN_CTX, BN_CTX_Deleter> ctx(BN_CTX_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> c(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> d(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> p(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> q(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> r(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> n(BN_new());
    
    BN_bin2bn(ciphertext.data(), ciphertext.size(), c.get());
    BN_bin2bn(privateKey.d.data(), privateKey.d.size(), d.get());
    BN_bin2bn(privateKey.p.data(), privateKey.p.size(), p.get());
    BN_bin2bn(privateKey.q.data(), privateKey.q.size(), q.get());
    BN_bin2bn(privateKey.r.data(), privateKey.r.size(), r.get());
    BN_bin2bn(privateKey.n.data(), privateKey.n.size(), n.get());

    // CRT Variables
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> p_minus_1(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> q_minus_1(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> r_minus_1(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> dp(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> dq(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> dr(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> m1(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> m2(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> m3(BN_new());

    BN_copy(p_minus_1.get(), p.get()); BN_sub_word(p_minus_1.get(), 1);
    BN_copy(q_minus_1.get(), q.get()); BN_sub_word(q_minus_1.get(), 1);
    BN_copy(r_minus_1.get(), r.get()); BN_sub_word(r_minus_1.get(), 1);

    BN_mod(dp.get(), d.get(), p_minus_1.get(), ctx.get());
    BN_mod(dq.get(), d.get(), q_minus_1.get(), ctx.get());
    BN_mod(dr.get(), d.get(), r_minus_1.get(), ctx.get());

    BN_mod_exp(m1.get(), c.get(), dp.get(), p.get(), ctx.get());
    BN_mod_exp(m2.get(), c.get(), dq.get(), q.get(), ctx.get());
    BN_mod_exp(m3.get(), c.get(), dr.get(), r.get(), ctx.get());

    // Reconstruct M using CRT
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> qr(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> pr(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> pq(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> qr_inv_p(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> pr_inv_q(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> pq_inv_r(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> t1(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> t2(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> t3(BN_new());
    std::unique_ptr<BIGNUM, BIGNUM_Deleter> m(BN_new());

    BN_mul(qr.get(), q.get(), r.get(), ctx.get());
    BN_mul(pr.get(), p.get(), r.get(), ctx.get());
    BN_mul(pq.get(), p.get(), q.get(), ctx.get());

    BN_mod_inverse(qr_inv_p.get(), qr.get(), p.get(), ctx.get());
    BN_mod_inverse(pr_inv_q.get(), pr.get(), q.get(), ctx.get());
    BN_mod_inverse(pq_inv_r.get(), pq.get(), r.get(), ctx.get());

    BN_mul(t1.get(), m1.get(), qr.get(), ctx.get()); BN_mul(t1.get(), t1.get(), qr_inv_p.get(), ctx.get());
    BN_mul(t2.get(), m2.get(), pr.get(), ctx.get()); BN_mul(t2.get(), t2.get(), pr_inv_q.get(), ctx.get());
    BN_mul(t3.get(), m3.get(), pq.get(), ctx.get()); BN_mul(t3.get(), t3.get(), pq_inv_r.get(), ctx.get());

    BN_add(m.get(), t1.get(), t2.get());
    BN_add(m.get(), m.get(), t3.get());
    BN_mod(m.get(), m.get(), n.get(), ctx.get());

    std::vector<uint8_t> plaintext(BN_num_bytes(m.get()));
    BN_bn2bin(m.get(), plaintext.data());
    return plaintext;
}