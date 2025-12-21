# Main Branch vs POX-Dev Branch - Comparison Index

**Repository:** faintdono/trusted-firmware-m  
**Comparison Date:** December 21, 2025  
**Branches Compared:** main vs pox-dev

---

## Quick Summary

The `pox-dev` branch contains significant development work focused on adding **Proof of Execution (POX)** capabilities to TF-M. This represents approximately **7-9 months of active development** with over **5,800 commits** and changes to **2,189 files**.

### Key Statistics
- **Files Changed:** 2,189
- **Commits Ahead:** 5,828
- **Lines Added:** 115,017
- **Lines Removed:** 574,981
- **Net Change:** -459,964 lines
- **Primary Feature:** Proof of Execution (POX) service
- **Main Developer:** Raned Chuphueak (19 POX-specific commits)

---

## Documentation Structure

This comparison consists of four detailed documents:

### 1. **BRANCH_COMPARISON.md** - Executive Overview
**Purpose:** High-level strategic comparison  
**Contents:**
- Executive summary with key statistics
- Proof of Execution feature overview
- Initial Attestation Token modifications
- Boot loader updates (BL1/BL2)
- Platform-specific changes
- Documentation updates
- Configuration and build system changes
- Cryptographic updates
- Branch divergence analysis
- Integration considerations and recommendations

**Read this first** for a strategic understanding of the differences.

### 2. **FILE_CHANGES_DETAIL.md** - Granular File Analysis
**Purpose:** Detailed file-by-file breakdown  
**Contents:**
- Complete file statistics (Added/Deleted/Modified/Renamed)
- POX-related new files listing
- Major changes organized by category:
  - Initial Attestation modifications
  - Boot Loader (BL1/BL2) changes
  - Platform support updates
  - Cryptographic library updates
  - Configuration and build system
  - Documentation changes
  - Testing infrastructure
- Notable deletions with context
- File renaming patterns
- Areas of concentrated change
- Merge complexity assessment per area
- Recommended merge strategy
- Risk assessment by component

**Read this** for understanding specific file changes and merge planning.

### 3. **POX_TECHNICAL_ANALYSIS.md** - Deep Technical Dive
**Purpose:** Technical implementation details of POX feature  
**Contents:**
- POX architecture overview
- Core components description:
  - POX Service Partition
  - Wire Protocol
  - IAT Integration
- Key technical features
- API design (public and secure)
- Implementation timeline (4 phases)
- Integration with TF-M architecture
- Platform support details
- Cryptographic design
- Testing considerations
- Performance impact analysis
- Known issues and fixes
- Dependencies
- Configuration options
- Future enhancement possibilities
- Comparison with standard IAT
- Documentation status
- Production readiness recommendations

**Read this** for technical implementation details and architecture understanding.

### 4. **COMMIT_HISTORY_COMPARISON.md** - Commit Analysis
(To be created - see below for preview)

---

## What is Proof of Execution (POX)?

POX is a new security feature that enables **runtime attestation of code execution**. It provides cryptographic proof that specific code was executed in a trusted environment.

### Key Capabilities:
- Execute arbitrary functions with cryptographic proof
- Generate signed execution reports
- Integrate with existing attestation tokens
- Support for CBOR-encoded outputs
- Secure partition isolation

### Use Cases:
- Verify critical security functions were executed
- Provide evidence of specific code paths taken
- Enable runtime trust verification
- Support remote attestation of execution

---

## Branch Relationship

```
main branch (official TF-M)
    |
    | (diverged)
    |
    ├─── pox-dev branch
    |    └─── Merged from: zephyrproject-rtos:main
    |    └─── +5,828 commits
    |    └─── POX feature development
    |    └─── Platform updates
    |    └─── Attestation enhancements
```

**Note:** The branches do not share a common recent merge base, indicating significant divergence.

---

## Top Contributors to pox-dev

Based on commit analysis (excluding merges):

| Rank | Developer | Commits | Affiliation (likely) |
|------|-----------|---------|---------------------|
| 1 | Raef Coles | 407 | ARM |
| 2 | David Hu | 379 | ARM |
| 3 | Antonio de Angelis | 349 | ARM |
| 4 | Kevin Peng | 314 | ARM |
| 5 | Jamie Fox | 242 | ARM |
| 6 | Summer Qin | 239 | ARM |
| 7 | Joakim Andersson | 211 | Nordic |
| 8 | Tamas Ban | 199 | ARM |
| 9 | Ken Liu | 179 | ARM |
| 10 | Chris Brand | 164 | Broadcom/Cypress |
| ... | ... | ... | ... |
| POX | Raned Chuphueak | 19 | POX Developer |

**POX-Specific Developer:**
- **Raned Chuphueak** (raned.chu@gmail.com) - 19 commits specifically for POX feature

---

## Timeline of Major Changes

### 9 months ago
- Platform updates (ADI MAX32657, Nordic nRF)
- Initial infrastructure work

### 7 months ago
- **POX Development Begins**
- Initial IAT modification for POX
- POX API added

### 4 months ago
- POX serialization implementation
- Wire protocol development
- Deserializer added

### 3 months ago
- Bug fixes (stack overflow, serializer issues)
- Arbitrary function support improved
- Token generation refined

### 2-3 months ago
- Output handling enhancements
- NS (Non-Secure) output integration
- CBOR encoding improvements

### Recent (Last 2 months)
- Active bug fixing and refinement
- Documentation updates
- Platform support expansion

---

## Critical Differences

### New Features in pox-dev:
1. ✅ **POX Service** - Complete new secure partition
2. ✅ **POX API** - Public interface for POX operations
3. ✅ **Wire Protocol** - Serialization for POX requests
4. ✅ **IAT Integration** - POX embedded in attestation tokens
5. ✅ **Platform Support** - Extended platform compatibility

### Modified Core Components:
1. ⚠️ **Attestation Service** - Significant modifications
2. ⚠️ **BL1/BL2** - Boot loader updates
3. ⚠️ **Crypto** - Enhanced cryptographic operations
4. ⚠️ **Build System** - CMake and Kconfig updates

### Removed Components:
1. ❌ Root README.md
2. ❌ Dummy attestation keys
3. ❌ Legacy configuration files
4. ❌ Some documentation files

---

## Merge Feasibility Assessment

### Challenges:
- **No Common Merge Base** - Branches have diverged significantly
- **5,800+ Commits** - Large number of changes to review
- **Core Modifications** - Critical security components changed
- **Platform Diversity** - Changes affect multiple platforms

### Prerequisites for Merge:
1. Complete security audit of POX feature
2. Comprehensive testing on all platforms
3. Documentation completion
4. Community review and acceptance
5. Compatibility layer for existing users
6. Migration guide preparation

### Estimated Effort:
- **Code Review:** 4-6 weeks
- **Testing:** 3-4 weeks
- **Documentation:** 2-3 weeks
- **Security Audit:** 2-4 weeks
- **Total:** 3-4 months minimum

---

## Recommendations

### For Project Maintainers:
1. **Review POX Feature** - Assess if POX aligns with TF-M roadmap
2. **Security Audit** - Commission independent security review
3. **Community Discussion** - Present POX to TF-M community
4. **Phased Integration** - Consider gradual merge strategy

### For Developers:
1. **Start with Analysis** - Read all comparison documents
2. **Test POX Branch** - Validate on your target platform
3. **Provide Feedback** - Report issues or improvements
4. **Documentation Review** - Check technical accuracy

### For Users:
1. **Evaluate Need** - Determine if POX features are required
2. **Stay on Main** - Unless POX is specifically needed
3. **Monitor Progress** - Watch for POX integration into main
4. **Test Integration** - If using pox-dev, test thoroughly

---

## Getting Started with These Documents

### For a Quick Overview:
Read: **BRANCH_COMPARISON.md** (15 min)

### For Merge Planning:
Read: **FILE_CHANGES_DETAIL.md** → **BRANCH_COMPARISON.md** (45 min)

### For Technical Understanding:
Read: **POX_TECHNICAL_ANALYSIS.md** → **BRANCH_COMPARISON.md** (60 min)

### For Complete Analysis:
Read all documents in order:
1. README_COMPARISON.md (this file) - 10 min
2. BRANCH_COMPARISON.md - 15 min
3. FILE_CHANGES_DETAIL.md - 20 min
4. POX_TECHNICAL_ANALYSIS.md - 30 min

**Total Time:** ~75 minutes

---

## Document Maintenance

These comparison documents were generated on **December 21, 2025** based on:
- **main branch** at commit: `e9ea674ed`
- **pox-dev branch** at commit: `0826d777a`

As both branches continue to evolve, these comparisons may become outdated. Re-generate comparison when:
- Significant changes occur in either branch
- Merge planning begins
- Major releases are cut
- Every 3-6 months for active branches

---

## Questions or Issues?

For questions about:
- **Main TF-M branch:** Contact TF-M maintainers
- **POX feature:** Contact Raned Chuphueak (raned.chu@gmail.com)
- **Merge planning:** Consult with TF-M technical steering committee
- **Platform-specific issues:** Contact respective platform maintainers

---

## Additional Resources

- TF-M Official Documentation: https://tf-m-user-guide.trustedfirmware.org/
- TF-M GitHub: https://github.com/TrustedFirmware-m/trusted-firmware-m
- PSA Specification: https://developer.arm.com/architectures/security-architectures/platform-security-architecture
- Entity Attestation Token (EAT): https://datatracker.ietf.org/doc/draft-ietf-rats-eat/

---

**End of Comparison Index**
