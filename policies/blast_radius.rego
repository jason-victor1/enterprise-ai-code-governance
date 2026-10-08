package enterprise.blast_radius

default allow = false

# Rule: Tier 1 changes require senior security signoff
deny[msg] {
    input.blast_radius.overall_tier == 1
    input.author_metadata.senior_security_approved == false
    msg := "[GOVERNANCE-TIER-01] Tier 1 critical path modified without mandatory Senior Security sign-off."
}

# Rule: Tier 1 and Tier 2 changes cannot be auto-merged
deny[msg] {
    input.blast_radius.overall_tier < 3
    input.blast_radius.eligible_for_auto_merge == true
    msg := sprintf("[GOVERNANCE-TIER-02] Risk Tier %v is ineligible for automated merge. Must complete manual verification.", [input.blast_radius.overall_tier])
}
