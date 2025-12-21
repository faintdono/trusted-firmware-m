# Quick Start Guide: Understanding main vs pox-dev Comparison

**⏱️ Time to read: 5 minutes**

## What You Need to Know

The `pox-dev` branch contains a major new feature called **Proof of Execution (POX)** that's been in development for 7-9 months. It has diverged significantly from the `main` branch with 5,828 commits and changes to 2,189 files.

## In 30 Seconds

- **What changed?** Added POX feature + platform updates + attestation enhancements
- **How much?** 2,189 files, 115k lines added, 575k lines removed (reorganization)
- **Risk level?** HIGH - Critical security components modified
- **Ready to merge?** NO - Needs security audit and extensive testing

## The 5 Documents Explained

We've created 5 comprehensive documents for you:

### 1️⃣ README_COMPARISON.md
**The Navigator** - Start here  
📊 Stats, timeline, and guide to other documents  
⏱️ 10 minutes

### 2️⃣ BRANCH_COMPARISON.md  
**The Executive Brief** - For decision makers  
🎯 High-level overview, recommendations, integration considerations  
⏱️ 15 minutes

### 3️⃣ FILE_CHANGES_DETAIL.md
**The Merge Planner** - For integration engineers  
📝 File-by-file breakdown, merge strategy, risk assessment  
⏱️ 20 minutes

### 4️⃣ POX_TECHNICAL_ANALYSIS.md
**The Technical Spec** - For developers  
🔧 Architecture, API design, implementation details  
⏱️ 30 minutes

### 5️⃣ VISUAL_SUMMARY.md
**The Visual Guide** - For visual learners  
📊 Charts, diagrams, timelines  
⏱️ 5 minutes

## Choose Your Path

### Path A: "I need to decide if we should merge this" (30 min)
1. Read VISUAL_SUMMARY.md (5 min)
2. Read BRANCH_COMPARISON.md (15 min)
3. Review recommendations section
4. Decision: Plan security audit and testing OR Stay on main branch

### Path B: "I need to plan a merge" (1 hour)
1. Read VISUAL_SUMMARY.md (5 min)
2. Read FILE_CHANGES_DETAIL.md (20 min)
3. Read BRANCH_COMPARISON.md (15 min)
4. Create merge plan based on recommendations

### Path C: "I need to understand POX technically" (1.5 hours)
1. Read VISUAL_SUMMARY.md (5 min)
2. Read POX_TECHNICAL_ANALYSIS.md (30 min)
3. Read BRANCH_COMPARISON.md (15 min)
4. Review POX source code on pox-dev branch

### Path D: "I just want the facts" (10 min)
1. Read VISUAL_SUMMARY.md (5 min)
2. Skim README_COMPARISON.md quick summary (5 min)
3. Done!

## Key Findings at a Glance

### ✅ What's Good
- Well-structured POX implementation
- Active development and bug fixing
- Comprehensive platform support updates
- Follows TF-M secure partition model

### ⚠️ What's Concerning
- No common merge base with main
- 5,828 commits to review
- Critical security components modified
- Limited POX-specific documentation
- Needs extensive testing

### 🔴 What's Critical
- Boot loader modifications (BL1/BL2)
- Attestation service changes
- New secure partition (POX)
- Cryptographic updates

## Should You Use pox-dev?

### Use pox-dev if:
- ✅ You specifically need Proof of Execution feature
- ✅ You can thoroughly test on your platform
- ✅ You can accept the risk of using non-mainline code
- ✅ You're willing to track upstream changes

### Stay on main if:
- ✅ You don't need POX
- ✅ You need stable, community-vetted code
- ✅ You prioritize security audited code
- ✅ You want official TF-M releases

## Immediate Actions

### For Maintainers
1. ⚠️ Review POX feature scope and goals
2. ⚠️ Commission security audit
3. ⚠️ Plan community discussion
4. 📋 Read BRANCH_COMPARISON.md for detailed recommendations

### For Developers
1. 📖 Read POX_TECHNICAL_ANALYSIS.md
2. 🧪 Test pox-dev on your platform
3. 📝 Report findings to repository maintainer
4. 🔍 Review code in secure_fw/partitions/proof_of_execution/

### For Users
1. ✅ Evaluate if POX is needed for your use case
2. ⏸️ Stay on main branch unless POX is required
3. 👀 Monitor for POX integration into main
4. 📋 Read BRANCH_COMPARISON.md for full context

## Quick Stats Cheat Sheet

```
Files Changed:    2,189
Commits Ahead:    5,828
Lines Added:      115,017
Lines Removed:    574,981
Time Span:        ~9 months
Main Feature:     Proof of Execution (POX)
Main Developer:   Raned Chuphueak (POX)
Risk Level:       HIGH
Test Coverage:    NEEDS IMPROVEMENT
Documentation:    PARTIAL
Ready to Merge:   NO (needs review)
```

## Common Questions

**Q: What is POX?**  
A: Proof of Execution - A feature that provides cryptographic proof that specific code was executed in a trusted environment.

**Q: Is pox-dev stable?**  
A: It's actively developed and being refined, but hasn't gone through mainline TF-M review and testing processes.

**Q: Can I merge pox-dev into my project?**  
A: Yes, but you'll need to thoroughly test it on your platform and understand the security implications.

**Q: Will POX be merged into main?**  
A: Unknown. That decision would be made by TF-M maintainers after review and community discussion.

**Q: How long to merge pox-dev to main?**  
A: Estimated 3-5 months minimum for proper review, testing, and phased integration.

## Getting Help

**For technical questions about POX:**
- Email: raned.chu@gmail.com (POX developer)

**For TF-M general questions:**
- TF-M Documentation: https://tf-m-user-guide.trustedfirmware.org/
- TF-M GitHub: https://github.com/TrustedFirmware-m/trusted-firmware-m

**For merge/integration questions:**
- Review FILE_CHANGES_DETAIL.md for merge strategy
- Contact TF-M maintainers

## Next Steps

1. Choose your path (A, B, C, or D above)
2. Read the relevant documents
3. Make your decision or create your plan
4. Take action based on recommendations

---

**Last Updated:** December 21, 2025  
**Branch Versions:**
- main: e9ea674ed
- pox-dev: 0826d777a

**Document Set:**
- QUICK_START_GUIDE.md ← You are here
- README_COMPARISON.md
- BRANCH_COMPARISON.md
- FILE_CHANGES_DETAIL.md
- POX_TECHNICAL_ANALYSIS.md
- VISUAL_SUMMARY.md
