export const {TlsClient} = (() => {
    const m = new TextEncoder, L = new Uint8Array(0),
        it = new Map([[4865, {id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0}], [4866, {id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0}], [49199, {id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"}], [49200, {id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}], [49195, {id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"}], [49196, {id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}]]),
        O = new Map([[29, "X25519"], [23, "P-256"]]), ht = [2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515], u = (...n) => {
            const t = i => {
                let r = 0;
                for (const c of i) c instanceof Uint8Array ? r += c.length : Array.isArray(c) ? r += t(c) : typeof c == "number" && (r += 1);
                return r
            }, s = new Uint8Array(t(n));
            let h = 0;
            const e = i => {for (const r of i) r instanceof Uint8Array ? (s.set(r, h), h += r.length) : Array.isArray(r) ? e(r) : typeof r == "number" && (s[h++] = r)};
            return e(n), s
        }, f = n => [n >> 8 & 255, 255 & n], _ = (n, t) => n[t] << 8 | n[t + 1], nt = (n, t) => n[t] << 16 | n[t + 1] << 8 | n[t + 2], b = (...n) => {
            const t = n.filter(i => i && i.length > 0), s = t.reduce((i, r) => i + r.length, 0), h = new Uint8Array(s);
            let e = 0;
            for (const i of t) h.set(i, e), e += i.length;
            return h
        }, Y = n => crypto.getRandomValues(new Uint8Array(n)), j = n => n === "SHA-384" ? 48 : 32, et = {key: m.encode("tls13 key"), iv: m.encode("tls13 iv"), derived: m.encode("tls13 derived"), finished: m.encode("tls13 finished"), chs: m.encode("tls13 c hs traffic"), shs: m.encode("tls13 s hs traffic"), cap: m.encode("tls13 c ap traffic"), sap: m.encode("tls13 s ap traffic")};
    async function B(n, t, s) {
        const h = t.type === "secret" ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: n}, !1, ["sign"]);
        return new Uint8Array(await crypto.subtle.sign("HMAC", h, s))
    }
    async function M(n, t) {return new Uint8Array(await crypto.subtle.digest(n, t))}
    async function G(n, t, s, h, e = "SHA-256") {
        const i = b(m.encode(t), s);
        let r = new Uint8Array(0), c = i;
        const l = n.type === "secret" ? n : await crypto.subtle.importKey("raw", n, {name: "HMAC", hash: e}, !1, ["sign"]);
        for (; r.length < h;) {
            c = await B(e, l, c);
            const a = await B(e, l, b(c, i));
            r = b(r, a)
        }
        return r.slice(0, h)
    }
    async function V(n, t, s) {return t && t.length || (t = new Uint8Array(j(n))), B(n, t, s)}
    async function q(n, t, s, h, e) {
        const i = typeof s == "string" ? et[s] || m.encode("tls13 " + s) : s, r = j(n), c = Math.ceil(e / r), l = u(f(e), i.length, i, h.length, h);
        let a = new Uint8Array(0), w = new Uint8Array(0);
        const p = t.type === "secret" ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: n}, !1, ["sign"]);
        for (let y = 1; y <= c; y++) w = await B(n, p, b(w, l, [y])), a = b(a, w);
        return a.slice(0, e)
    }
    async function Z(n = "P-256") {
        if (n === "X25519") {
            const s = await crypto.subtle.generateKey({name: "X25519"}, !0, ["deriveBits"]);
            return {kp: s, pk: new Uint8Array(await crypto.subtle.exportKey("raw", s.publicKey))}
        }
        const t = await crypto.subtle.generateKey({name: "ECDH", namedCurve: n}, !0, ["deriveBits"]);
        return {kp: t, pk: new Uint8Array(await crypto.subtle.exportKey("raw", t.publicKey))}
    }
    async function $(n, t, s = "P-256") {
        if (s === "X25519") {
            const e = await crypto.subtle.importKey("raw", t, {name: "X25519"}, !1, []);
            return new Uint8Array(await crypto.subtle.deriveBits({name: "X25519", public: e}, n, 256))
        }
        const h = await crypto.subtle.importKey("raw", t, {name: "ECDH", namedCurve: s}, !1, []);
        return new Uint8Array(await crypto.subtle.deriveBits({name: "ECDH", public: h}, n, 256))
    }
    async function W(n, t) {return crypto.subtle.importKey("raw", n, {name: "AES-GCM"}, !1, [t])}
    async function R(n, t, s, h) {return new Uint8Array(await crypto.subtle.encrypt({name: "AES-GCM", iv: t, additionalData: h, tagLength: 128}, n, s))}
    async function N(n, t, s, h) {return new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: t, additionalData: h, tagLength: 128}, n, s))}
    function v(n, t, s = 771) {
        const h = new Uint8Array(5 + t.length);
        return h[0] = n, h[1] = s >> 8, h[2] = 255 & s, h[3] = t.length >> 8, h[4] = 255 & t.length, h.set(t, 5), h
    }
    function K(n, t) {
        const s = new Uint8Array(4 + t.length);
        return s[0] = n, s[1] = t.length >> 16 & 255, s[2] = t.length >> 8 & 255, s[3] = 255 & t.length, s.set(t, 4), s
    }
    class rt {
        constructor() {this.b = new Uint8Array(32768), this.h = 0, this.t = 0}
        feed(t) {
            if (this.t + t.length > this.b.length) {
                if (this.t - this.h + t.length > this.b.length) {
                    const s = new Uint8Array(Math.max(this.b.length * 2, this.t - this.h + t.length));
                    s.set(this.b.subarray(this.h, this.t), 0), this.b = s
                } else {
                    this.b.copyWithin(0, this.h, this.t);
                }
                this.t -= this.h, this.h = 0
            }
            this.b.set(t, this.t), this.t += t.length
        }
        next() {
            if (this.t - this.h < 5) return null;
            const t = this.b[this.h], s = _(this.b, this.h + 1), h = _(this.b, this.h + 3);
            if (h > 18432) throw new Error;
            if (this.t - this.h < 5 + h) return null;
            const e = this.b.subarray(this.h + 5, this.h + 5 + h);
            return this.h += 5 + h, this.h === this.t && (this.h = this.t = 0), {type: t, version: s, length: h, fragment: e}
        }
    }
    class at {
        constructor() {this.b = new Uint8Array(4096), this.h = 0, this.t = 0}
        feed(t) {
            if (this.t + t.length > this.b.length) {
                if (this.t - this.h + t.length > this.b.length) {
                    const s = new Uint8Array(Math.max(this.b.length * 2, this.t - this.h + t.length));
                    s.set(this.b.subarray(this.h, this.t), 0), this.b = s
                } else {
                    this.b.copyWithin(0, this.h, this.t);
                }
                this.t -= this.h, this.h = 0
            }
            this.b.set(t, this.t), this.t += t.length
        }
        next() {
            if (this.t - this.h < 4) return null;
            const t = this.b[this.h], s = nt(this.b, this.h + 1);
            if (this.t - this.h < 4 + s) return null;
            const h = this.b.subarray(this.h + 4, this.h + 4 + s), e = this.b.subarray(this.h, this.h + 4 + s);
            return this.h += 4 + s, this.h === this.t && (this.h = this.t = 0), {type: t, length: s, body: h, raw: e}
        }
    }
    const D = n => n && n[0] === 1 && n[1] === 112;
    function ct(n, t, s, {sessionId: h = L} = {}) {
        const e = [4865, 4866, 49199, 49200, 49195, 49196], i = u(...e.flatMap(f)), r = [u(255, 1, 0, 1, 0)];
        if (t) {
            const p = m.encode(t), y = u(0, f(p.length), p);
            r.push(u(f(0), f(y.length + 2), f(y.length), y))
        }
        r.push(u(f(11), 0, 2, 1, 0));
        const c = u(0, 29, 0, 23);
        r.push(u(f(10), f(c.length + 2), f(c.length), c));
        const l = u(...ht.flatMap(f));
        r.push(u(f(13), f(l.length + 2), f(l.length), l)), r.push(u(f(43), 0, 5, 4, 3, 4, 3, 3)), r.push(u(f(45), 0, 2, 1, 1));
        const a = b(u(0, 29, f(s.x25519.length), s.x25519), u(0, 23, f(s.p256.length), s.p256));
        r.push(u(f(51), f(a.length + 2), f(a.length), a));
        const w = b(...r);
        return K(1, u(f(771), n, h.length, h, f(i.length), i, 1, 0, f(w.length), w))
    }
    const T = async (n, t, s, h, e) => {
        const i = t.type === "secret" ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: n}, !1, ["sign"]), [r, c] = await Promise.all([q(n, i, "key", L, s), q(n, i, "iv", L, h)]);
        return [await W(r, e), c]
    }, Q = n => {
        let t = n.length - 1;
        for (; t >= 0 && n[t] === 0;) t--;
        if (t < 0) throw new Error;
        return {data: n.subarray(0, t), type: n[t]}
    }, I = (n, t) => {
        const s = n.slice();
        for (let h = 0; h < 8; h++) s[s.length - 1 - h] ^= Number(t >> BigInt(8 * h) & 0xffn);
        return s
    };
    class lt {
        constructor(t, s = {}) {this.sk = t, this.sn = s.serverName || "", this.cr = Y(32), this.id = Y(32), this.sr = null, this.hb = new Uint8Array(8192), this.hl = 0, this.hc = !1, this.cs = null, this.cc = null, this.i3 = !1, this.ms = null, this.hs = null, this.ck = null, this.wk = null, this.cv = null, this.wv = null, this.ch = null, this.sh = null, this.ci = null, this.si = null, this.ak = null, this.bk = null, this.ai = null, this.bi = null, this.cn = 0n, this.qn = 0n, this.rp = new rt, this.hp = new at, this.kp = new Map, this.pq = [], this.cl = !1, this.cg = !1, this.fl = !1, this.wq = Promise.resolve(), this.cp = null, this.rb = new Uint8Array(65536), this.rd = null, this.wr = null}
        rh(t) {
            if (this.hl + t.length > this.hb.length) {
                const s = new Uint8Array(Math.max(this.hb.length * 2, this.hl + t.length));
                s.set(this.hb.subarray(0, this.hl), 0), this.hb = s
            }
            this.hb.set(t, this.hl), this.hl += t.length
        }
        ts() {return this.hb.subarray(0, this.hl)}
        fc() {return this.cn++}
        fs() {return this.qn++}
        fail() {this.fl = !0, this.cl = !0, this.sk?.close()}
        async rc() {
            const t = await this.rd.read(this.rb);
            if (t) return !t.done && t.value && (this.rb = new Uint8Array(t.value.buffer)), t;
            throw new Error
        }
        async pr(t) {
            for (; ;) {
                let s;
                for (; s = this.rp.next();) if (await t(s)) return;
                const {value: h, done: e} = await this.rc();
                if (e) throw new Error;
                this.rp.feed(h)
            }
        }
        async handshake() {
            const [t, s] = await Promise.all([Z("P-256"), Z("X25519")]);
            this.kp = new Map([[23, t], [29, s]]), this.rd = this.sk.readable.getReader({mode: "byob"}), this.wr = this.sk.writable.getWriter();
            try {
                const h = {p256: t.pk, x25519: s.pk}, e = ct(this.cr, this.sn, h, {sessionId: this.id});
                this.rh(e), await this.wr.write(v(22, e, 769));
                let i = await this.rsh();
                if (i.isTls13) {
                    const r = i, c = O.get(r.ks?.group);
                    if (!c || !r.ks?.key?.length) throw new Error;
                    const l = this.kp.get(r.ks.group);
                    if (!l) throw new Error;
                    const a = this.cc.hash, w = j(a), p = this.cc.keyLen, y = this.cc.ivLen, P = await $(l.kp.privateKey, r.ks.key, c), g = await V(a, null, new Uint8Array(w)), U = await q(a, g, "derived", await M(a, L), w);
                    this.hs = await V(a, U, P);
                    const d = await M(a, this.ts()), C = await q(a, this.hs, "chs", d, w), H = await q(a, this.hs, "shs", d, w);
                    [this.ch, this.ci] = await T(a, C, p, y, "encrypt"), [this.sh, this.si] = await T(a, H, p, y, "decrypt");
                    let E = !1, x = !1;
                    const S = async k => {this.rh(k.raw), k.type === 13 ? x = !0 : k.type === 20 && (E = !0)};
                    await this.pr(async k => {
                        if (k.type === 20 || k.type === 22) return;
                        if (k.type === 21) {
                            if (D(k.fragment)) return;
                            throw new Error
                        }
                        if (k.type !== 23) return;
                        const pt = I(this.si, this.fs()), gt = new Uint8Array([23, 3, 3, k.fragment.length >> 8, 255 & k.fragment.length]), bt = await N(this.sh, pt, k.fragment, gt), {data: dt, type: kt} = Q(bt);
                        if (kt === 22) {
                            this.hp.feed(dt);
                            for (let st; st = this.hp.next();) if (await S(st), E) return 1
                        }
                    });
                    const o = await M(a, this.ts()), A = await q(a, this.hs, "derived", await M(a, L), w), X = await V(a, A, new Uint8Array(w)), z = await q(a, X, "cap", o, w), ot = await q(a, X, "sap", o, w);
                    [this.ak, this.ai] = await T(a, z, p, y, "encrypt"), [this.bk, this.bi] = await T(a, ot, p, y, "decrypt");
                    let F = L;
                    x && (F = K(11, u(0, 0, 0, 0)), this.rh(F));
                    const wt = await q(a, C, "finished", L, w), ft = await B(a, wt, await M(a, this.ts())), tt = K(20, ft);
                    this.rh(tt);
                    const J = b(F, tt, [22]), yt = I(this.ci, this.fc()), ut = new Uint8Array([23, 3, 3, J.length + 16 >> 8, 255 & J.length + 16]);
                    await this.wr.write(v(23, await R(this.ch, yt, J, ut))), this.cn = 0n, this.qn = 0n
                } else {
                    let r = null, c = !1, l = !1;
                    const a = async o => {
                        switch (o.type) {
                            case 11:
                                this.rh(o.raw);
                                break;
                            case 12: {
                                this.rh(o.raw);
                                let A = 1;
                                const X = _(o.body, A);
                                A += 2;
                                const z = o.body[A++];
                                r = {nc: X, spk: o.body.subarray(A, A + z)};
                                break
                            }
                            case 14:
                                return this.rh(o.raw), c = !0, 1;
                            case 13:
                                this.rh(o.raw), l = !0;
                                break;
                            default:
                                this.rh(o.raw)
                        }
                    };
                    let w = !1;
                    for (let o; o = this.hp.next();) if (await a(o)) {
                        w = !0;
                        break
                    }
                    if (w || await this.pr(async o => {
                        if (o.type === 21) {
                            if (D(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 22) {
                            this.hp.feed(o.fragment);
                            for (let A; A = this.hp.next();) if (await a(A)) return 1
                        }
                    }), !c) {
                        throw new Error;
                    }
                    if (!r) throw new Error;
                    const p = O.get(r.nc);
                    if (!p) throw new Error;
                    const y = this.kp.get(r.nc);
                    if (!y) throw new Error;
                    if (l) {
                        const o = K(11, u(0, 0, 0));
                        this.rh(o), await this.wr.write(v(22, o))
                    }
                    const P = await $(y.kp.privateKey, r.spk, p), g = K(16, u(y.pk.length, y.pk));
                    this.rh(g);
                    const U = this.cc.hash;
                    this.ms = await G(P, "master secret", b(this.cr, this.sr), 48, U);
                    const d = this.cc.keyLen, C = this.cc.ivLen, H = await G(this.ms, "key expansion", b(this.sr, this.cr), 2 * d + 2 * C, U);
                    [this.ck, this.wk] = await Promise.all([W(H.subarray(0, d), "encrypt"), W(H.subarray(d, 2 * d), "decrypt")]), this.cv = H.subarray(2 * d, 2 * d + C), this.wv = H.subarray(2 * d + C, 2 * d + 2 * C), await this.wr.write(v(22, g)), await this.wr.write(v(20, u(1)));
                    const E = await G(this.ms, "client finished", await M(U, this.ts()), 12, U), x = K(20, E);
                    this.rh(x), await this.wr.write(v(22, await this.e12(x, 22)));
                    let S = !1;
                    await this.pr(async o => {
                        if (o.type === 21) {
                            if (D(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 20) return void (S = !0);
                        if (o.type !== 22 || !S) return;
                        if ((await this.d12(o.fragment, 22))[0] === 20) return 1
                    })
                }
                this.hc = !0, this.cr = this.id = this.sr = this.ms = this.hs = this.ch = this.sh = this.ci = this.si = null, this.kp.clear(), this.kp = null
            } finally {
                if (!this.hc || this.fl) {
                    try {this.rd?.releaseLock()} catch {}
                    try {this.wr?.releaseLock()} catch {}
                }
            }
        }
        async rsh() {
            for (; ;) {
                const {value: t, done: s} = await this.rc();
                if (s) throw new Error;
                let h;
                for (this.rp.feed(t); h = this.rp.next();) {
                    if (h.type === 21) {
                        if (D(h.fragment)) continue;
                        throw new Error
                    }
                    if (h.type !== 22) continue;
                    let e;
                    for (this.hp.feed(h.fragment); e = this.hp.next();) {
                        if (e.type !== 2) continue;
                        this.rh(e.raw);
                        let i = 0;
                        const r = _(e.body, i);
                        i += 2;
                        const c = e.body.slice(i, i + 32);
                        i += 32;
                        const l = e.body[i++], a = e.body.subarray(i, i + l);
                        i += l;
                        const w = _(e.body, i);
                        i += 2;
                        const p = e.body[i++];
                        let y = r, P = null;
                        if (i < e.body.length) {
                            const d = _(e.body, i);
                            i += 2;
                            const C = i + d;
                            for (; i + 4 <= C;) {
                                const H = _(e.body, i);
                                i += 2;
                                const E = _(e.body, i);
                                i += 2;
                                const x = e.body.subarray(i, i + E);
                                if (i += E, H === 43 && E >= 2) {
                                    y = _(x, 0);
                                } else if (H === 51 && E >= 2) {
                                    const S = _(x, 0), o = E >= 4 ? _(x, 2) : 0;
                                    P = {group: S, key: o ? x.subarray(4, 4 + o) : L}
                                }
                            }
                        }
                        const g = {version: r, sr: c, sid: a, cs: w, comp: p, sv: y, ks: P, isTls13: y === 772}, U = it.get(g.cs) || null;
                        if (!U || g.comp || g.isTls13 !== !!U.tls13 || !g.isTls13 && g.sv !== 771) throw new Error;
                        return this.sr = g.sr, this.cs = g.cs, this.cc = U, this.i3 = g.isTls13, g
                    }
                }
            }
        }
        async e12(t, s, h = this.fc()) {
            const e = new Uint8Array(8);
            new DataView(e.buffer).setBigUint64(0, h, !1);
            const i = new Uint8Array(13);
            i.set(e, 0), i[8] = s, i[9] = 3, i[10] = 3, i[11] = t.length >> 8, i[12] = 255 & t.length;
            const r = new Uint8Array(this.cv.length + 8);
            r.set(this.cv, 0), r.set(e, this.cv.length);
            const c = await R(this.ck, r, t, i), l = new Uint8Array(8 + c.length);
            return l.set(e, 0), l.set(c, 8), l
        }
        async d12(t, s, h = this.fs()) {
            const e = new Uint8Array(8);
            new DataView(e.buffer).setBigUint64(0, h, !1);
            const i = t.subarray(0, 8), r = t.subarray(8), c = new Uint8Array(13);
            c.set(e, 0), c[8] = s, c[9] = 3, c[10] = 3, c[11] = r.length - 16 >> 8, c[12] = 255 & r.length - 16;
            const l = new Uint8Array(this.wv.length + 8);
            return l.set(this.wv, 0), l.set(i, this.wv.length), N(this.wk, l, r, c)
        }
        async e13(t, s = this.fc(), h = 23) {
            const e = new Uint8Array(t.length + 1);
            e.set(t, 0), e[t.length] = h;
            const i = I(this.ai, s), r = new Uint8Array([23, 3, 3, e.length + 16 >> 8, 255 & e.length + 16]);
            return R(this.ak, i, e, r)
        }
        async d13(t, s = this.fs(), h = this.bk, e = this.bi) {
            const i = I(e, s), r = new Uint8Array([23, 3, 3, t.length >> 8, 255 & t.length]), c = await N(h, i, t, r);
            return Q(c)
        }
        write(t) {
            if (!this.hc || this.fl || this.cg) return Promise.reject(new Error);
            const s = this.wq.then(async () => {
                if (this.fl || this.cg) throw new Error;
                if (t.length <= 16384) {
                    await this.wr.write(v(23, this.i3 ? await this.e13(t) : await this.e12(t, 23)));
                } else {
                    for (let e = 0; e < t.length;) {
                        const i = [];
                        for (let r = 0; r < 8 && e < t.length; r++, e += 16384) {
                            const c = t.subarray(e, Math.min(e + 16384, t.length)), l = this.fc();
                            i.push(this.i3 ? this.e13(c, l).then(a => v(23, a)) : this.e12(c, 23, l).then(a => v(23, a)))
                        }
                        await this.wr.write(b(...await Promise.all(i)))
                    }
                }
            }), h = s.catch(e => {throw this.fail(), e});
            return this.wq = h.catch(() => {}), h
        }
        read() {
            return this.fl || !this.hc ? Promise.reject(new Error) : (async () => {
                for (; ;) {
                    if (this.pq.length) {
                        const i = this.pq.length === 1 ? this.pq[0] : b(...this.pq);
                        return this.pq = [], i
                    }
                    if (this.cl) return null;
                    const t = [];
                    let s;
                    for (; t.length < 8 && (s = this.rp.next());) {
                        if (this.i3) {
                            if (s.type === 20) continue;
                            if (s.type !== 23) throw new Error
                        } else if (s.type !== 23 && s.type !== 21 && s.type !== 22) throw new Error;
                        t.push(s)
                    }
                    if (t.length) {
                        if (this.i3) {
                            const i = this.qn, r = this.bk, c = this.bi;
                            let l;
                            try {l = await Promise.all(t.map((a, w) => this.d13(a.fragment, i + BigInt(w), r, c)))} catch {l = null}
                            if (l) {
                                this.qn = i + BigInt(l.length);
                                for (let a = 0; a < l.length; a++) this.p13(l[a])
                            } else {
                                for (let a = 0; a < t.length; a++) {
                                    const w = await this.d13(t[a].fragment, this.qn);
                                    this.qn++, this.p13(w)
                                }
                            }
                        } else {
                            const i = this.qn, r = await Promise.all(t.map((c, l) => this.d12(c.fragment, c.type, i + BigInt(l))));
                            this.qn = i + BigInt(t.length);
                            for (let c = 0; c < r.length; c++) {
                                const l = r[c], a = t[c].type;
                                if (a === 23) {
                                    this.pq.push(l);
                                } else if (a === 21) {
                                    this.pa(l);
                                } else if (a === 22) {
                                    let w;
                                    for (this.hp.feed(l); w = this.hp.next();) ;
                                }
                            }
                        }
                        if (this.pq.length) {
                            const i = this.pq.length === 1 ? this.pq[0] : b(...this.pq);
                            return this.pq = [], i
                        }
                        if (this.cl) return null;
                        continue
                    }
                    if (this.cl) return null;
                    const {value: h, done: e} = await this.rc();
                    if (e) return null;
                    this.rp.feed(h)
                }
            })().catch(t => {throw this.fail(), t})
        }
        pa(t) {this.cl = !0, this.close()}
        p13({data: t, type: s}) {s === 23 ? this.pq.push(t) : s === 21 && this.pa(t)}
        close() {
            if (this.cp) return this.cp;
            if (this.fl || !this.hc) return this.sk?.close(), this.cp = Promise.resolve();
            this.cg = !0;
            const t = this.wq.then(async () => {
                const s = new Uint8Array([1, 0]), h = this.i3 ? await this.e13(s, this.fc(), 21) : await this.e12(s, 21);
                await this.wr.write(v(this.i3 ? 23 : 21, h))
            });
            return this.cp = t.catch(() => {}).finally(() => {this.cl = !0, this.sk?.close()}), this.wq = this.cp, this.cp
        }
    }
    return {TlsClient: lt}
})();
