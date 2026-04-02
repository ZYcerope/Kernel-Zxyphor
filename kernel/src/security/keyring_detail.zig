// SPDX-License-Identifier: GPL-2.0
// Zxyphor Kernel - Keyring & Key Management Subsystem
// Complete: keyctl interface, key types, key quotas, asymmetric keys,
// trusted/encrypted keys, PKCS#7/X.509, keyring search/link/garbage collection

const std = @import("std");

// ============================================================================
// Key Types
// ============================================================================

pub const KeyType = enum(u8) {
    User = 0,
    Logon = 1,
    Keyring = 2,
    BigKey = 3,
    Trusted = 4,
    Encrypted = 5,
    Asymmetric = 6,
    DnsResolver = 7,
    IdMap = 8,
    Ceph = 9,
    Rxrpc = 10,
    RxrpcS = 11,
    Blacklist = 12,
    Lockdown = 13,
    MachineTrusted = 14,
    PlatformTrusted = 15,
};

pub const KeyPermissions = packed struct(u32) {
    possessor_view: bool,
    possessor_read: bool,
    possessor_write: bool,
    possessor_search: bool,
    possessor_link: bool,
    possessor_setattr: bool,
    possessor_inval: bool,
    possessor_revoke: bool,
    user_view: bool,
    user_read: bool,
    user_write: bool,
    user_search: bool,
    user_link: bool,
    user_setattr: bool,
    user_inval: bool,
    user_revoke: bool,
    group_view: bool,
    group_read: bool,
    group_write: bool,
    group_search: bool,
    group_link: bool,
    group_setattr: bool,
    group_inval: bool,
    group_revoke: bool,
    other_view: bool,
    other_read: bool,
    other_write: bool,
    other_search: bool,
    other_link: bool,
    other_setattr: bool,
    other_inval: bool,
    other_revoke: bool,
};

pub const KeyFlags = packed struct(u32) {
    dead: bool,
    revoked: bool,
    in_quota: bool,
    user_construct: bool,
    negative: bool,
    invalidated: bool,
    builtin: bool,
    root_can_inval: bool,
    root_can_clear: bool,
    keep: bool,
    uid_keyring: bool,
    _reserved: u21,
};

pub const KeyState = enum(u8) {
    Uninstantiated = 0,
    Instantiated = 1,
    Negative = 2,
    Revoked = 3,
    Dead = 4,
    Expired = 5,
};

// ============================================================================
// Key Structure
// ============================================================================

pub const Key = struct {
    usage: u32,              // Reference count
    serial: i32,             // Key serial number
    type_data: KeyTypeData,
    flags: KeyFlags,
    state: KeyState,
    uid: u32,                // Owner UID
    gid: u32,               // Owner GID
    perm: KeyPermissions,
    quotalen: u16,           // Quota charge
    datalen: u32,            // Length of payload
    description: [256]u8,    // Key description
    expiry: i64,             // Expiry time (0 = never)
    last_used_at: i64,
    domain_tag: ?*KeyTag,
    key_type: ?*const KeyTypeOps,
    payload: KeyPayload,
    security: ?*anyopaque,   // LSM security pointer
    restrict_link: ?*KeyRestriction,
    sem: u64,                // RW semaphore
};

pub const KeyPayload = struct {
    rcu_data0: ?*anyopaque,
    data: [4]?*anyopaque,
};

pub const KeyTag = struct {
    usage: u32,
    removed: bool,
    tag_name: [64]u8,
};

pub const KeyTypeData = union {
    reject_error: i32,
    type_data2: [2]u64,
};

// ============================================================================
// Key Type Operations
// ============================================================================

pub const KeyTypeOps = struct {
    name: [32]u8,
    def_datalen: u32,
    flags: u32,
    vet_description: ?*const fn (desc: [*]const u8) callconv(.C) i32,
    preparse: ?*const fn (prep: *KeyPreparsedPayload) callconv(.C) i32,
    free_preparse: ?*const fn (prep: *KeyPreparsedPayload) callconv(.C) void,
    instantiate: ?*const fn (key: *Key, prep: *KeyPreparsedPayload) callconv(.C) i32,
    update: ?*const fn (key: *Key, prep: *KeyPreparsedPayload) callconv(.C) i32,
    match_preparse: ?*const fn (parse: *KeyMatchData) callconv(.C) i32,
    match_free: ?*const fn (parse: *KeyMatchData) callconv(.C) void,
    revoke: ?*const fn (key: *Key) callconv(.C) void,
    destroy: ?*const fn (key: *Key) callconv(.C) void,
    describe: ?*const fn (key: *Key, buf: [*]u8, len: usize) callconv(.C) usize,
    read: ?*const fn (key: *Key, buf: [*]u8, len: usize) callconv(.C) i64,
    request_key: ?*const fn (auth_key: *Key, aux: [*]const u8, auxlen: usize) callconv(.C) i32,
    lookup_restriction: ?*const fn (restriction: [*]const u8) callconv(.C) ?*KeyRestriction,
    asym_query: ?*const fn (params: *const KeyTypeAsymQuery, key: *Key) callconv(.C) i32,
    asym_eds_op: ?*const fn (params: *KeyTypeAsymEdsOp, key: *Key, sig: [*]u8, sig_len: *usize) callconv(.C) i32,
    asym_verify_signature: ?*const fn (params: *KeyTypeAsymVerify, key: *Key) callconv(.C) i32,
};

pub const KeyPreparsedPayload = struct {
    orig_description: ?[*]const u8,
    description: [256]u8,
    payload: KeyPayload,
    data: ?[*]const u8,
    datalen: usize,
    quotalen: u16,
    expiry: i64,
};

pub const KeyMatchData = struct {
    cmp: ?*const fn (key: *const Key, match_data: *const KeyMatchData) callconv(.C) bool,
    raw_data: ?*const anyopaque,
    preparsed: ?*anyopaque,
    lookup_type: u32,
};

pub const KeyRestriction = struct {
    check: ?*const fn (keyring: *Key, key_type: *const KeyTypeOps, payload: *const KeyPayload, restriction_key: *Key) callconv(.C) i32,
    key: ?*Key,
    keytype: ?*const KeyTypeOps,
};

// ============================================================================
// Asymmetric Key
// ============================================================================

pub const KeyTypeAsymQuery = struct {
    encoding: [16]u8,
    hash_algo: [16]u8,
    pkey_algo: [16]u8,
    supported_ops: u32,
};

pub const KeyTypeAsymEdsOp = struct {
    encoding: [16]u8,
    hash_algo: [16]u8,
    in_data: ?[*]const u8,
    in_len: usize,
    out_data: ?[*]u8,
    out_len: usize,
    op: AsymOpType,
};

pub const AsymOpType = enum(u8) {
    Encrypt = 0,
    Decrypt = 1,
    Sign = 2,
    Verify = 3,
};

pub const KeyTypeAsymVerify = struct {
    encoding: [16]u8,
    hash_algo: [16]u8,
    digest: [*]const u8,
    digest_len: usize,
    sig: [*]const u8,
    sig_len: usize,
};

pub const AsymmetricKeyIds = struct {
    id: [3]?*AsymKeyId,
};

pub const AsymKeyId = struct {
    len: u32,
    data: [64]u8,
};

pub const PublicKey = struct {
    key: ?[*]const u8,
    keylen: u32,
    key_is_private: bool,
    id_type: [16]u8,
    pkey_algo: [16]u8,
    encoding: [16]u8,
    params: ?[*]const u8,
    paramlen: u32,
};

pub const PublicKeySignature = struct {
    s: ?[*]const u8,
    s_size: u32,
    digest: ?[*]const u8,
    digest_size: u32,
    pkey_algo: [16]u8,
    hash_algo: [16]u8,
    encoding: [16]u8,
    auth_ids: [3]?*AsymKeyId,
};

// ============================================================================
// X.509 Certificate
// ============================================================================

pub const X509Certificate = struct {
    pub_key: PublicKey,
    sig: PublicKeySignature,
    issuer: [256]u8,
    subject: [256]u8,
    id: ?*AsymKeyId,
    skid: ?*AsymKeyId,
    serial: [40]u8,
    serial_len: u32,
    valid_from: i64,
    valid_to: i64,
    raw_serial: [128]u8,
    raw_serial_size: u32,
    raw_issuer: [512]u8,
    raw_issuer_size: u32,
    raw_subject: [512]u8,
    raw_subject_size: u32,
    raw_skid: [64]u8,
    raw_skid_size: u32,
    index: u32,
    seen: bool,
    verified: bool,
    self_signed: bool,
    unsupported_crypto: bool,
    unsupported_key: bool,
    unsupported_sig: bool,
    blacklisted: bool,
};

// ============================================================================
// PKCS#7 Signed Data
// ============================================================================

pub const Pkcs7Message = struct {
    certs: ?*X509Certificate,
    crl: ?*anyopaque,
    signed_infos: ?*Pkcs7SignedInfo,
    data: ?[*]const u8,
    data_len: usize,
    data_hdrlen: usize,
    data_type: u32,
    have_authattrs: bool,
    unsupported_crypto: bool,
};

pub const Pkcs7SignedInfo = struct {
    next: ?*Pkcs7SignedInfo,
    signer: ?*X509Certificate,
    issuer: [256]u8,
    serial: [40]u8,
    serial_len: u32,
    sig: PublicKeySignature,
    index: u32,
    unsupported_crypto: bool,
    blacklisted: bool,
    aa_set: u32,
    msgdigest: [64]u8,
    msgdigest_len: u32,
    signing_time: i64,
    smime_cap: ?*anyopaque,
};

// ============================================================================
// Trusted Key
// ============================================================================

pub const TrustedKeyPayload = struct {
    key: [128]u8,       // Key material
    key_len: u32,
    blob: [4096]u8,     // Sealed blob
    blob_len: u32,
    old_format: bool,
    migratable: bool,
};

pub const TrustedKeyOps = struct {
    name: [16]u8,
    seal: ?*const fn (payload: *TrustedKeyPayload, options: [*]const u8) callconv(.C) i32,
    unseal: ?*const fn (payload: *TrustedKeyPayload, options: [*]const u8) callconv(.C) i32,
    get_random: ?*const fn (buf: [*]u8, len: usize) callconv(.C) i32,
    init: ?*const fn () callconv(.C) i32,
    exit: ?*const fn () callconv(.C) void,
};

pub const TrustedKeySource = enum(u8) {
    Tpm = 0,
    Tee = 1,
    Caam = 2,
    Dcp = 3,
};

// ============================================================================
// Encrypted Key
// ============================================================================

pub const EncryptedKeyPayload = struct {
    format: [16]u8,
    master_desc: [256]u8,
    datalen: u32,
    decrypted_datalen: u32,
    decrypted_data: [4096]u8,
    encrypted_data: [4096 + 64]u8,   // + auth tag
    encrypted_datalen: u32,
    key_derivation: EncKeyDerivation,
    cipher: [32]u8,
    hash: [32]u8,
    iv: [16]u8,
    hmac: [32]u8,
};

pub const EncKeyDerivation = enum(u8) {
    Default = 0,    // AES-256-CTS
    Ecryptfs = 1,   // eCryptfs format
};

// ============================================================================
// Keyctl System Call Interface
// ============================================================================

pub const KeyctlOp = enum(u32) {
    GET_KEYRING_ID = 0,
    JOIN_SESSION_KEYRING = 1,
    UPDATE = 2,
    REVOKE = 3,
    CHOWN = 4,
    SETPERM = 5,
    DESCRIBE = 6,
    CLEAR = 7,
    LINK = 8,
    UNLINK = 9,
    SEARCH = 10,
    READ = 11,
    INSTANTIATE = 12,
    NEGATE = 13,
    SET_REQKEY_KEYRING = 14,
    SET_TIMEOUT = 15,
    ASSUME_AUTHORITY = 16,
    GET_SECURITY = 17,
    SESSION_TO_PARENT = 18,
    REJECT = 19,
    INSTANTIATE_IOV = 20,
    INVALIDATE = 21,
    GET_PERSISTENT = 22,
    DH_COMPUTE = 23,
    PKEY_QUERY = 24,
    PKEY_ENCRYPT = 25,
    PKEY_DECRYPT = 26,
    PKEY_SIGN = 27,
    PKEY_VERIFY = 28,
    RESTRICT_KEYRING = 29,
    MOVE = 30,
    CAPABILITIES = 31,
    WATCH_KEY = 32,
};

pub const KeyspecialId = enum(i32) {
    KEY_SPEC_THREAD_KEYRING = -1,
    KEY_SPEC_PROCESS_KEYRING = -2,
    KEY_SPEC_SESSION_KEYRING = -3,
    KEY_SPEC_USER_KEYRING = -4,
    KEY_SPEC_USER_SESSION_KEYRING = -5,
    KEY_SPEC_GROUP_KEYRING = -6,
    KEY_SPEC_REQKEY_AUTH_KEY = -7,
    KEY_SPEC_REQUESTOR_KEYRING = -8,
};

pub const KeyReqkeyDest = enum(u8) {
    KEY_REQKEY_DEFL_NO_CHANGE = 0,
    KEY_REQKEY_DEFL_DEFAULT = 1,
    KEY_REQKEY_DEFL_THREAD_KEYRING = 2,
    KEY_REQKEY_DEFL_PROCESS_KEYRING = 3,
    KEY_REQKEY_DEFL_SESSION_KEYRING = 4,
    KEY_REQKEY_DEFL_USER_KEYRING = 5,
    KEY_REQKEY_DEFL_USER_SESSION_KEYRING = 6,
    KEY_REQKEY_DEFL_GROUP_KEYRING = 7,
    KEY_REQKEY_DEFL_REQUESTOR_KEYRING = 8,
};

// ============================================================================
// DH Compute
// ============================================================================

pub const KeyctlDhParams = struct {
    private_key: i32,    // Key serial
    prime: i32,          // Key serial
    base: i32,           // Key serial
};

pub const KeyctlKdfParams = struct {
    hashname: [32]u8,
    otherinfo: ?[*]const u8,
    otherinfolen: u32,
};

// ============================================================================
// Keyring Quota
// ============================================================================

pub const KeyQuota = struct {
    maxkeys: u32,
    maxbytes: u32,
    cur_keys: u32,
    cur_bytes: u32,
};

pub const KeyUser = struct {
    uid: u32,
    usage: u32,
    nkeys: u32,
    nikeys: u32,
    qnkeys: u32,
    qnbytes: u32,
};

// ============================================================================
// Keyring Search
// ============================================================================

pub const KeyringSearchContext = struct {
    index_key: KeyringIndexKey,
    match_data: KeyMatchData,
    flags: u32,
    result: ?*Key,
    cred: ?*anyopaque,
    now: i64,
};

pub const KeyringIndexKey = struct {
    hash: u32,
    desc_len: u32,
    key_type: ?*const KeyTypeOps,
    description: [256]u8,
    domain_tag: ?*KeyTag,
};

pub const KeyringListEntry = struct {
    key: ?*Key,
    next: ?*KeyringListEntry,
};

pub const KeyringList = struct {
    usage: u32,
    nkeys: u16,
    maxkeys: u16,
    keys: [256]?*Key,
};

// ============================================================================
// GC (Garbage Collection)
// ============================================================================

pub const KeyGcState = enum(u8) {
    Idle = 0,
    Scanning = 1,
    Reaping = 2,
};

pub const KeyGcStats = struct {
    scans: u64,
    keys_expired: u64,
    keys_revoked: u64,
    keys_gc: u64,
    keyrings_gc: u64,
    last_gc_time: i64,
};

// ============================================================================
// Manager
// ============================================================================

pub const KeyringManager = struct {
    session_keyring: ?*Key,
    user_keyring: ?*Key,
    process_keyring: ?*Key,
    thread_keyring: ?*Key,
    total_keys: u64,
    total_keyrings: u64,
    gc_stats: KeyGcStats,
    quota: KeyQuota,
    initialized: bool,

    pub fn init() KeyringManager {
        return .{
            .session_keyring = null,
            .user_keyring = null,
            .process_keyring = null,
            .thread_keyring = null,
            .total_keys = 0,
            .total_keyrings = 0,
            .gc_stats = std.mem.zeroes(KeyGcStats),
            .quota = .{
                .maxkeys = 200,
                .maxbytes = 20000,
                .cur_keys = 0,
                .cur_bytes = 0,
            },
            .initialized = true,
        };
    }
};
