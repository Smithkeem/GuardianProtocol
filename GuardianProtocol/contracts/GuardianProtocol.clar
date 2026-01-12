;; Automated Compliance with Dynamic Policies

;; This smart contract implements an automated compliance system that enforces
;; dynamic policies for regulated activities. It allows administrators to define
;; and update compliance rules, verify user compliance status, and automatically
;; enforce restrictions based on policy violations. The system supports multi-tier
;; compliance levels, temporal policy enforcement, and audit trails for regulatory reporting.

;; constants

;; Error codes for contract operations
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-POLICY-NOT-FOUND (err u101))
(define-constant ERR-INVALID-COMPLIANCE-LEVEL (err u102))
(define-constant ERR-USER-NOT-COMPLIANT (err u103))
(define-constant ERR-POLICY-EXPIRED (err u104))
(define-constant ERR-THRESHOLD-EXCEEDED (err u105))
(define-constant ERR-ALREADY-EXISTS (err u106))
(define-constant ERR-INVALID-PARAMETER (err u107))

;; Contract administrator principal
(define-constant CONTRACT-OWNER tx-sender)

;; Compliance level constants
(define-constant COMPLIANCE-LEVEL-NONE u0)
(define-constant COMPLIANCE-LEVEL-BASIC u1)
(define-constant COMPLIANCE-LEVEL-STANDARD u2)
(define-constant COMPLIANCE-LEVEL-ADVANCED u3)
(define-constant COMPLIANCE-LEVEL-PREMIUM u4)

;; Maximum values for security constraints
(define-constant MAX-POLICY-DURATION u52560000) ;; ~10 years in blocks
(define-constant MAX-VIOLATION-COUNT u100)

;; data maps and vars

;; Stores compliance policies with their rules and requirements
;; Maps policy-id to policy details including required compliance level and expiration
(define-map policies
    { policy-id: uint }
    {
        policy-name: (string-ascii 50),
        required-level: uint,
        expiration-height: uint,
        active: bool,
        min-reputation-score: uint,
        max-violation-count: uint,
        created-by: principal,
        created-at: uint
    }
)

;; Tracks user compliance status and history
;; Maps user principal to their current compliance state
(define-map user-compliance
    { user: principal }
    {
        compliance-level: uint,
        reputation-score: uint,
        violation-count: uint,
        last-verified: uint,
        verification-expiry: uint,
        is-blacklisted: bool
    }
)

;; Records policy violations for audit purposes
;; Maps user and violation-id to violation details
(define-map violations
    { user: principal, violation-id: uint }
    {
        policy-id: uint,
        violation-type: (string-ascii 50),
        severity: uint,
        recorded-at: uint,
        resolved: bool
    }
)

;; Tracks which users have been approved for specific policies
;; Maps user and policy-id to approval status
(define-map policy-approvals
    { user: principal, policy-id: uint }
    {
        approved: bool,
        approved-at: uint,
        approved-by: principal,
        expires-at: uint
    }
)

;; Stores authorized compliance officers who can manage policies
(define-map authorized-officers
    { officer: principal }
    { authorized: bool, granted-at: uint }
)

;; Global state variables
(define-data-var next-policy-id uint u1)
(define-data-var next-violation-id uint u1)
(define-data-var total-policies-created uint u0)
(define-data-var total-violations-recorded uint u0)

;; private functions

;; Checks if the caller is the contract owner
;; @returns: bool - true if caller is owner, false otherwise
(define-private (is-contract-owner)
    (is-eq tx-sender CONTRACT-OWNER)
)

;; Checks if the caller is an authorized compliance officer
;; @param officer: principal - the principal to check
;; @returns: bool - true if authorized, false otherwise
(define-private (is-authorized-officer (officer principal))
    (default-to false 
        (get authorized (map-get? authorized-officers { officer: officer }))
    )
)

;; Validates that a compliance level is within acceptable range
;; @param level: uint - the compliance level to validate
;; @returns: bool - true if valid, false otherwise
(define-private (is-valid-compliance-level (level uint))
    (and 
        (>= level COMPLIANCE-LEVEL-NONE)
        (<= level COMPLIANCE-LEVEL-PREMIUM)
    )
)

;; Checks if a policy is currently active and not expired
;; @param policy-id: uint - the policy identifier
;; @returns: bool - true if active and valid, false otherwise
(define-private (is-policy-active (policy-id uint))
    (match (map-get? policies { policy-id: policy-id })
        policy-data
        (and
            (get active policy-data)
            (>= (get expiration-height policy-data) block-height)
        )
        false
    )
)

;; Calculates if a user meets the requirements for a specific policy
;; @param user: principal - the user to check
;; @param policy-id: uint - the policy to check against
;; @returns: bool - true if user meets requirements, false otherwise
(define-private (user-meets-policy-requirements (user principal) (policy-id uint))
    (match (map-get? policies { policy-id: policy-id })
        policy-data
        (match (map-get? user-compliance { user: user })
            user-data
            (and
                (>= (get compliance-level user-data) (get required-level policy-data))
                (>= (get reputation-score user-data) (get min-reputation-score policy-data))
                (<= (get violation-count user-data) (get max-violation-count policy-data))
                (not (get is-blacklisted user-data))
                (>= (get verification-expiry user-data) block-height)
            )
            false
        )
        false
    )
)

;; public functions

;; Initializes a new user in the compliance system with basic level
;; @param user: principal - the user to register
;; @returns: (response bool uint) - success or error code
(define-public (register-user (user principal))
    (begin
        ;; Ensure user doesn't already exist to prevent accidental overwrites
        (asserts! (is-none (map-get? user-compliance { user: user })) ERR-ALREADY-EXISTS)
        
        ;; Create new user compliance record with default values
        (ok (map-set user-compliance
            { user: user }
            {
                compliance-level: COMPLIANCE-LEVEL-BASIC,
                reputation-score: u50,
                violation-count: u0,
                last-verified: block-height,
                verification-expiry: (+ block-height u52560), ;; ~1 year validity
                is-blacklisted: false
            }
        ))
    )
)

;; Creates a new compliance policy with specified requirements
;; Only authorized officers or contract owner can create policies
;; @param policy-name: (string-ascii 50) - descriptive name for the policy
;; @param required-level: uint - minimum compliance level required
;; @param duration: uint - policy validity duration in blocks
;; @param min-reputation: uint - minimum reputation score required
;; @param max-violations: uint - maximum allowed violations
;; @returns: (response uint uint) - policy-id on success or error code
(define-public (create-policy 
    (policy-name (string-ascii 50))
    (required-level uint)
    (duration uint)
    (min-reputation uint)
    (max-violations uint))
    (let
        (
            (caller tx-sender)
            (current-policy-id (var-get next-policy-id))
        )
        ;; Security check: only authorized officers can create policies
        (asserts! 
            (or (is-contract-owner) (is-authorized-officer caller))
            ERR-NOT-AUTHORIZED
        )
        
        ;; Validate compliance level is within acceptable range
        (asserts! (is-valid-compliance-level required-level) ERR-INVALID-COMPLIANCE-LEVEL)
        
        ;; Validate duration doesn't exceed maximum allowed
        (asserts! (<= duration MAX-POLICY-DURATION) ERR-INVALID-PARAMETER)
        
        ;; Validate max-violations is within bounds
        (asserts! (<= max-violations MAX-VIOLATION-COUNT) ERR-INVALID-PARAMETER)
        
        ;; Create the policy with all specified parameters
        (map-set policies
            { policy-id: current-policy-id }
            {
                policy-name: policy-name,
                required-level: required-level,
                expiration-height: (+ block-height duration),
                active: true,
                min-reputation-score: min-reputation,
                max-violation-count: max-violations,
                created-by: caller,
                created-at: block-height
            }
        )
        
        ;; Update global state counters
        (var-set next-policy-id (+ current-policy-id u1))
        (var-set total-policies-created (+ (var-get total-policies-created) u1))
        
        ;; Return the newly created policy ID
        (ok current-policy-id)
    )
)

;; Verifies if a user is compliant with a specific policy
;; This is a read-only check that doesn't modify state
;; @param user: principal - the user to verify
;; @param policy-id: uint - the policy to check against
;; @returns: (response bool uint) - true if compliant, error code otherwise
(define-public (verify-compliance (user principal) (policy-id uint))
    (begin
        ;; Check if policy exists and is active
        (asserts! (is-policy-active policy-id) ERR-POLICY-NOT-FOUND)
        
        ;; Verify user meets all policy requirements
        (asserts! (user-meets-policy-requirements user policy-id) ERR-USER-NOT-COMPLIANT)
        
        ;; Return success if all checks pass
        (ok true)
    )
)

;; Records a compliance violation for a user
;; Only authorized officers can record violations
;; @param violator: principal - the user who violated the policy
;; @param policy-id: uint - the policy that was violated
;; @param violation-type: (string-ascii 50) - description of violation
;; @param severity: uint - severity level (1-10)
;; @returns: (response uint uint) - violation-id on success or error code
(define-public (record-violation
    (violator principal)
    (policy-id uint)
    (violation-type (string-ascii 50))
    (severity uint))
    (let
        (
            (caller tx-sender)
            (current-violation-id (var-get next-violation-id))
            (user-data-option (map-get? user-compliance { user: violator }))
        )
        ;; Only authorized officers can record violations
        (asserts! 
            (or (is-contract-owner) (is-authorized-officer caller))
            ERR-NOT-AUTHORIZED
        )
        
        ;; Validate that the policy exists
        (asserts! (is-some (map-get? policies { policy-id: policy-id })) ERR-POLICY-NOT-FOUND)
        
        ;; Validate severity is within range (1-10)
        (asserts! (and (>= severity u1) (<= severity u10)) ERR-INVALID-PARAMETER)
        
        ;; Record the violation
        (map-set violations
            { user: violator, violation-id: current-violation-id }
            {
                policy-id: policy-id,
                violation-type: violation-type,
                severity: severity,
                recorded-at: block-height,
                resolved: false
            }
        )
        
        ;; Update user's violation count if user exists in system
        (match user-data-option
            user-data
            (map-set user-compliance
                { user: violator }
                (merge user-data { 
                    violation-count: (+ (get violation-count user-data) u1)
                })
            )
            true ;; User not in system yet, violation still recorded
        )
        
        ;; Update global counters
        (var-set next-violation-id (+ current-violation-id u1))
        (var-set total-violations-recorded (+ (var-get total-violations-recorded) u1))
        
        (ok current-violation-id)
    )
)

;; Updates a user's compliance level and reputation score
;; Only authorized officers can update compliance status
;; @param user: principal - the user to update
;; @param new-level: uint - new compliance level
;; @param new-reputation: uint - new reputation score
;; @param verification-duration: uint - how long the verification is valid
;; @returns: (response bool uint) - success or error code
(define-public (update-user-compliance
    (user principal)
    (new-level uint)
    (new-reputation uint)
    (verification-duration uint))
    (let
        (
            (caller tx-sender)
            (user-data-option (map-get? user-compliance { user: user }))
        )
        ;; Only authorized officers can update compliance
        (asserts! 
            (or (is-contract-owner) (is-authorized-officer caller))
            ERR-NOT-AUTHORIZED
        )
        
        ;; Validate new compliance level
        (asserts! (is-valid-compliance-level new-level) ERR-INVALID-COMPLIANCE-LEVEL)
        
        ;; Validate verification duration
        (asserts! (<= verification-duration MAX-POLICY-DURATION) ERR-INVALID-PARAMETER)
        
        ;; User must exist in system
        (asserts! (is-some user-data-option) ERR-POLICY-NOT-FOUND)
        
        ;; Update user compliance data
        (match user-data-option
            user-data
            (ok (map-set user-compliance
                { user: user }
                (merge user-data {
                    compliance-level: new-level,
                    reputation-score: new-reputation,
                    last-verified: block-height,
                    verification-expiry: (+ block-height verification-duration)
                })
            ))
            ERR-POLICY-NOT-FOUND
        )
    )
)

;; Grants authorization to a compliance officer
;; Only contract owner can authorize officers
;; @param officer: principal - the principal to authorize
;; @returns: (response bool uint) - success or error code
(define-public (authorize-officer (officer principal))
    (begin
        ;; Only contract owner can authorize officers
        (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
        
        ;; Grant authorization with timestamp
        (ok (map-set authorized-officers
            { officer: officer }
            { authorized: true, granted-at: block-height }
        ))
    )
)

;; Approves a user for a specific policy after verification
;; Only authorized officers can grant approvals
;; @param user: principal - the user to approve
;; @param policy-id: uint - the policy to approve for
;; @param approval-duration: uint - how long the approval is valid (in blocks)
;; @returns: (response bool uint) - success or error code
(define-public (approve-user-for-policy
    (user principal)
    (policy-id uint)
    (approval-duration uint))
    (let
        (
            (caller tx-sender)
        )
        ;; Only authorized officers can approve users
        (asserts! 
            (or (is-contract-owner) (is-authorized-officer caller))
            ERR-NOT-AUTHORIZED
        )
        
        ;; Validate policy exists and is active
        (asserts! (is-policy-active policy-id) ERR-POLICY-NOT-FOUND)
        
        ;; Validate approval duration
        (asserts! (<= approval-duration MAX-POLICY-DURATION) ERR-INVALID-PARAMETER)
        
        ;; Verify user meets policy requirements before approval
        (asserts! (user-meets-policy-requirements user policy-id) ERR-USER-NOT-COMPLIANT)
        
        ;; Grant approval with expiration timestamp
        (ok (map-set policy-approvals
            { user: user, policy-id: policy-id }
            {
                approved: true,
                approved-at: block-height,
                approved-by: caller,
                expires-at: (+ block-height approval-duration)
            }
        ))
    )
)

;; Comprehensive compliance check with automatic policy enforcement
;; This function performs a multi-layer verification including policy status,
;; user compliance level, reputation score, violation history, blacklist status,
;; verification expiry, and policy-specific approvals. It's designed to be called
;; before any regulated activity to ensure full compliance with dynamic policies.
;; @param user: principal - the user requesting access to regulated activity
;; @param policy-id: uint - the policy that governs the activity
;; @param required-reputation-boost: uint - additional reputation required beyond policy minimum
;; @returns: (response bool uint) - true if all compliance checks pass, error code otherwise
(define-public (enforce-compliance-with-approval
    (user principal)
    (policy-id uint)
    (required-reputation-boost uint))
    (let
        (
            ;; Retrieve policy data, user compliance data, and approval data
            (policy-data-option (map-get? policies { policy-id: policy-id }))
            (user-data-option (map-get? user-compliance { user: user }))
            (approval-data-option (map-get? policy-approvals { user: user, policy-id: policy-id }))
        )
        ;; Step 1: Validate that policy exists
        (asserts! (is-some policy-data-option) ERR-POLICY-NOT-FOUND)
        
        ;; Step 2: Validate that user is registered in compliance system
        (asserts! (is-some user-data-option) ERR-USER-NOT-COMPLIANT)
        
        ;; Step 3: Check policy is active and not expired
        (asserts! (is-policy-active policy-id) ERR-POLICY-EXPIRED)
        
        ;; Step 4: Perform detailed compliance verification
        (match policy-data-option
            policy-data
            (match user-data-option
                user-data
                (begin
                    ;; Check 4a: User is not blacklisted
                    (asserts! (not (get is-blacklisted user-data)) ERR-USER-NOT-COMPLIANT)
                    
                    ;; Check 4b: User's verification hasn't expired
                    (asserts! (>= (get verification-expiry user-data) block-height) ERR-POLICY-EXPIRED)
                    
                    ;; Check 4c: User meets minimum compliance level requirement
                    (asserts! 
                        (>= (get compliance-level user-data) (get required-level policy-data))
                        ERR-INVALID-COMPLIANCE-LEVEL
                    )
                    
                    ;; Check 4d: User meets reputation score with additional boost requirement
                    (asserts! 
                        (>= (get reputation-score user-data) 
                            (+ (get min-reputation-score policy-data) required-reputation-boost))
                        ERR-USER-NOT-COMPLIANT
                    )
                    
                    ;; Check 4e: User hasn't exceeded maximum violation count
                    (asserts! 
                        (<= (get violation-count user-data) (get max-violation-count policy-data))
                        ERR-THRESHOLD-EXCEEDED
                    )
                    
                    ;; Step 5: Verify policy-specific approval exists and is valid
                    (match approval-data-option
                        approval-data
                        (begin
                            ;; Check 5a: Approval is marked as approved
                            (asserts! (get approved approval-data) ERR-NOT-AUTHORIZED)
                            
                            ;; Check 5b: Approval hasn't expired
                            (asserts! (>= (get expires-at approval-data) block-height) ERR-POLICY-EXPIRED)
                            
                            ;; All compliance checks passed successfully
                            (ok true)
                        )
                        ;; No approval found for this user-policy combination
                        ERR-NOT-AUTHORIZED
                    )
                )
                ERR-USER-NOT-COMPLIANT
            )
            ERR-POLICY-NOT-FOUND
        )
    )
)


