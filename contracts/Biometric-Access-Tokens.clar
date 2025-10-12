(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u401))
(define-constant ERR-INVALID-BIOMETRIC (err u402))
(define-constant ERR-TOKEN-EXPIRED (err u403))
(define-constant ERR-ORACLE-NOT-FOUND (err u404))
(define-constant ERR-BIOMETRIC-EXISTS (err u405))
(define-constant ERR-TOKEN-NOT-FOUND (err u406))

(define-constant ERR-DELEGATION-NOT-FOUND (err u409))
(define-constant ERR-DELEGATION-EXPIRED (err u410))
(define-constant ERR-DELEGATION-CHAIN-LIMIT (err u411))
(define-constant ERR-SELF-DELEGATION (err u412))

(define-constant ERR-SESSION-NOT-FOUND (err u407))
(define-constant ERR-SESSION-EXPIRED (err u408))

(define-map biometric-registry
    { user: principal }
    {
        biometric-hash: (buff 64),
        registered-at: uint,
        active: bool,
    }
)

(define-map access-tokens
    { token-id: uint }
    {
        user: principal,
        expires-at: uint,
        created-at: uint,
        revoked: bool,
    }
)

(define-map authorized-oracles
    { oracle: principal }
    {
        active: bool,
        reputation: uint,
    }
)

(define-data-var token-counter uint u0)
(define-data-var oracle-threshold uint u1)

(define-read-only (get-biometric-data (user principal))
    (map-get? biometric-registry { user: user })
)

(define-read-only (get-access-token (token-id uint))
    (map-get? access-tokens { token-id: token-id })
)

(define-read-only (is-oracle-authorized (oracle principal))
    (match (map-get? authorized-oracles { oracle: oracle })
        oracle-data (get active oracle-data)
        false
    )
)

(define-read-only (is-token-valid (token-id uint))
    (match (get-access-token token-id)
        token-data (and
            (< stacks-block-height (get expires-at token-data))
            (not (get revoked token-data))
        )
        false
    )
)

(define-public (register-biometric (biometric-hash (buff 64)))
    (let ((user tx-sender))
        (asserts! (is-none (get-biometric-data user)) ERR-BIOMETRIC-EXISTS)
        (map-set biometric-registry { user: user } {
            biometric-hash: biometric-hash,
            registered-at: stacks-block-height,
            active: true,
        })
        (ok true)
    )
)

(define-public (add-oracle (oracle principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (map-set authorized-oracles { oracle: oracle } {
            active: true,
            reputation: u100,
        })
        (ok true)
    )
)

(define-public (remove-oracle (oracle principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (map-delete authorized-oracles { oracle: oracle })
        (ok true)
    )
)

(define-public (verify-biometric-and-mint-token
        (user principal)
        (biometric-hash (buff 64))
        (duration uint)
    )
    (let (
            (current-token-id (+ (var-get token-counter) u1))
            (expires-at (+ stacks-block-height duration))
        )
        (asserts! (is-oracle-authorized tx-sender) ERR-UNAUTHORIZED)

        (match (get-biometric-data user)
            user-biometric (begin
                (asserts!
                    (is-eq (get biometric-hash user-biometric) biometric-hash)
                    ERR-INVALID-BIOMETRIC
                )
                (asserts! (get active user-biometric) ERR-INVALID-BIOMETRIC)

                (map-set access-tokens { token-id: current-token-id } {
                    user: user,
                    expires-at: expires-at,
                    created-at: stacks-block-height,
                    revoked: false,
                })

                (var-set token-counter current-token-id)
                (ok current-token-id)
            )
            ERR-INVALID-BIOMETRIC
        )
    )
)

(define-public (revoke-token (token-id uint))
    (match (get-access-token token-id)
        token-data (begin
            (asserts!
                (or
                    (is-eq tx-sender (get user token-data))
                    (is-eq tx-sender CONTRACT-OWNER)
                )
                ERR-UNAUTHORIZED
            )
            (map-set access-tokens { token-id: token-id }
                (merge token-data { revoked: true })
            )
            (ok true)
        )
        ERR-TOKEN-NOT-FOUND
    )
)

(define-public (update-biometric (new-biometric-hash (buff 64)))
    (let ((user tx-sender))
        (match (get-biometric-data user)
            user-biometric (begin
                (map-set biometric-registry { user: user }
                    (merge user-biometric { biometric-hash: new-biometric-hash })
                )
                (ok true)
            )
            ERR-INVALID-BIOMETRIC
        )
    )
)

(define-public (deactivate-biometric)
    (let ((user tx-sender))
        (match (get-biometric-data user)
            user-biometric (begin
                (map-set biometric-registry { user: user }
                    (merge user-biometric { active: false })
                )
                (ok true)
            )
            ERR-INVALID-BIOMETRIC
        )
    )
)

(define-public (access-protected-resource (token-id uint))
    (match (get-access-token token-id)
        token-data (begin
            (asserts! (is-eq tx-sender (get user token-data)) ERR-UNAUTHORIZED)
            (asserts! (is-token-valid token-id) ERR-TOKEN-EXPIRED)
            (ok "Access granted")
        )
        ERR-TOKEN-NOT-FOUND
    )
)

(define-private (revoke-token-internal (token-id uint))
    (match (get-access-token token-id)
        token-data (begin
            (map-set access-tokens { token-id: token-id }
                (merge token-data { revoked: true })
            )
            true
        )
        false
    )
)

(define-public (batch-revoke-tokens (token-id uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
        (revoke-token-internal token-id)
        (ok true)
    )
)

(define-read-only (get-user-tokens (user principal))
    (let ((token-count (var-get token-counter)))
        (if (> token-count u0)
            (list token-count)
            (list)
        )
    )
)

(define-read-only (get-contract-stats)
    {
        total-tokens: (var-get token-counter),
        oracle-threshold: (var-get oracle-threshold),
    }
)




(define-map biometric-sessions
    { session-id: uint }
    {
        user: principal,
        expires-at: uint,
        created-at: uint,
        active: bool,
        activity-count: uint,
    }
)

(define-map session-activities
    { session-id: uint, activity-index: uint }
    {
        action: (string-ascii 50),
        timestamp: uint,
    }
)

(define-data-var session-counter uint u0)
(define-data-var default-session-duration uint u144)

(define-read-only (get-session (session-id uint))
    (map-get? biometric-sessions { session-id: session-id })
)

(define-read-only (is-session-valid (session-id uint))
    (match (get-session session-id)
        session-data (and
            (< stacks-block-height (get expires-at session-data))
            (get active session-data)
        )
        false
    )
)

(define-public (create-biometric-session 
        (user principal) 
        (biometric-hash (buff 64))
        (duration uint)
    )
    (let (
            (current-session-id (+ (var-get session-counter) u1))
            (expires-at (+ stacks-block-height 
                (if (> duration u0) duration (var-get default-session-duration))
            ))
        )
        (asserts! (is-oracle-authorized tx-sender) ERR-UNAUTHORIZED)
        
        (match (get-biometric-data user)
            user-biometric (begin
                (asserts!
                    (is-eq (get biometric-hash user-biometric) biometric-hash)
                    ERR-INVALID-BIOMETRIC
                )
                (asserts! (get active user-biometric) ERR-INVALID-BIOMETRIC)
                
                (map-set biometric-sessions { session-id: current-session-id } {
                    user: user,
                    expires-at: expires-at,
                    created-at: stacks-block-height,
                    active: true,
                    activity-count: u0,
                })
                
                (var-set session-counter current-session-id)
                (ok current-session-id)
            )
            ERR-INVALID-BIOMETRIC
        )
    )
)

(define-public (execute-with-session (session-id uint) (action (string-ascii 50)))
    (match (get-session session-id)
        session-data (begin
            (asserts! (is-eq tx-sender (get user session-data)) ERR-UNAUTHORIZED)
            (asserts! (is-session-valid session-id) ERR-SESSION-EXPIRED)
            
            (let ((activity-index (get activity-count session-data)))
                (map-set session-activities 
                    { session-id: session-id, activity-index: activity-index }
                    {
                        action: action,
                        timestamp: stacks-block-height,
                    }
                )
                
                (map-set biometric-sessions { session-id: session-id }
                    (merge session-data { activity-count: (+ activity-index u1) })
                )
                
                (ok "Session action executed")
            )
        )
        ERR-SESSION-NOT-FOUND
    )
)

(define-public (terminate-session (session-id uint))
    (match (get-session session-id)
        session-data (begin
            (asserts!
                (or
                    (is-eq tx-sender (get user session-data))
                    (is-eq tx-sender CONTRACT-OWNER)
                )
                ERR-UNAUTHORIZED
            )
            
            (map-set biometric-sessions { session-id: session-id }
                (merge session-data { active: false })
            )
            (ok true)
        )
        ERR-SESSION-NOT-FOUND
    )
)

(define-map delegation-registry
    { delegation-id: uint }
    {
        delegator: principal,
        delegate: principal,
        expires-at: uint,
        created-at: uint,
        revoked: bool,
        max-depth: uint,
    }
)

(define-data-var delegation-counter uint u0)

(define-read-only (get-delegation (delegation-id uint))
    (map-get? delegation-registry { delegation-id: delegation-id })
)

(define-read-only (is-delegation-valid (delegation-id uint))
    (match (get-delegation delegation-id)
        delegation-data (and
            (< stacks-block-height (get expires-at delegation-data))
            (not (get revoked delegation-data))
        )
        false
    )
)

(define-public (create-delegation 
        (delegate principal)
        (duration uint)
        (max-depth uint)
    )
    (let (
            (current-delegation-id (+ (var-get delegation-counter) u1))
            (expires-at (+ stacks-block-height duration))
        )
        (asserts! (not (is-eq tx-sender delegate)) ERR-SELF-DELEGATION)
        (asserts! (<= max-depth u3) ERR-DELEGATION-CHAIN-LIMIT)
        
        (match (get-biometric-data tx-sender)
            user-biometric (begin
                (asserts! (get active user-biometric) ERR-INVALID-BIOMETRIC)
                
                (map-set delegation-registry { delegation-id: current-delegation-id } {
                    delegator: tx-sender,
                    delegate: delegate,
                    expires-at: expires-at,
                    created-at: stacks-block-height,
                    revoked: false,
                    max-depth: max-depth,
                })
                
                (var-set delegation-counter current-delegation-id)
                (ok current-delegation-id)
            )
            ERR-INVALID-BIOMETRIC
        )
    )
)

(define-public (revoke-delegation (delegation-id uint))
    (match (get-delegation delegation-id)
        delegation-data (begin
            (asserts!
                (or
                    (is-eq tx-sender (get delegator delegation-data))
                    (is-eq tx-sender CONTRACT-OWNER)
                )
                ERR-UNAUTHORIZED
            )
            (map-set delegation-registry { delegation-id: delegation-id }
                (merge delegation-data { revoked: true })
            )
            (ok true)
        )
        ERR-DELEGATION-NOT-FOUND
    )
)