(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u401))
(define-constant ERR-INVALID-BIOMETRIC (err u402))
(define-constant ERR-TOKEN-EXPIRED (err u403))
(define-constant ERR-ORACLE-NOT-FOUND (err u404))
(define-constant ERR-BIOMETRIC-EXISTS (err u405))
(define-constant ERR-TOKEN-NOT-FOUND (err u406))

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
