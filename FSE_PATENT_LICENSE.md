# Fused Semantic Execution (FSE) Patent License

## Patent Status

Fused Semantic Execution (FSE) is the subject of a pending patent application by Michael A. Kuykendall. All rights reserved.

**Patent Pending** — Application filed, patent rights claimed.

## Grant of License

This software is licensed under the MIT License (see LICENSE file). However, the following additional terms apply specifically to the Fused Semantic Execution (FSE) implementation found in `src/policy/fse/`:

### Permitted Uses

You MAY:
- Use this software (Gatewarden) for its intended purpose: Keygen.sh license validation
- Modify, distribute, and create derivative works of Gatewarden under the MIT License
- Study the FSE implementation for educational purposes
- Reference this implementation in academic work (with proper citation)

### Restricted Uses

You MAY NOT:
- Extract the FSE implementation from Gatewarden and use it as a standalone component in other projects
- Port the FSE architecture/algorithm to other programming languages for use outside of Gatewarden
- Implement the FSE algorithm in your own software based on studying this code
- Use the FSE implementation for any purpose other than Keygen.sh license validation through Gatewarden
- Create competing license validation libraries that implement the FSE algorithm

## Rationale

The FSE algorithm represents novel intellectual property that is the subject of a pending patent. While Gatewarden itself is open source under MIT, the specific FSE implementation is provided for use **only within the context of Gatewarden's intended purpose**.

If you wish to use FSE for purposes beyond Gatewarden's scope, please contact Michael A. Kuykendall at michaelallenkuykendall@gmail.com to discuss licensing options.

## What This Means in Practice

**✅ You can:**
- Use Gatewarden in your commercial product
- Fork Gatewarden and modify it for your needs
- Contribute to Gatewarden
- Read and learn from the FSE code

**❌ You cannot:**
- Copy the FSE algorithm into your own policy engine
- Build a competing product using FSE
- Implement FSE in another language based on this code
- Use FSE for non-license-validation use cases (e.g., API gateways, feature flags) without permission

## Patent Claims

The pending patent covers:
1. Selector-first, single-pass rule evaluation architecture
2. Deduplication of selectors at compile time to achieve O(M) runtime where M = unique selectors
3. Value broadcast pattern where one selector extraction serves all dependent rules
4. Fail-closed semantics with unresolved required rules forced to False at finalization
5. Early exit optimization when all required rules are resolved

## Citation

If you reference this work in academic publications, please cite:

```
Kuykendall, M. A. (2026). Fused Semantic Execution: A Selector-First Rule Evaluation Architecture. 
Gatewarden (Version 0.3.0) [Computer software]. https://github.com/Michael-A-Kuykendall/gatewarden
```

## Questions

For licensing inquiries, patent questions, or permission requests:
- Email: michaelallenkuykendall@gmail.com
- GitHub: @Michael-A-Kuykendall

---

**Last Updated:** June 5, 2026  
**Patent Application Status:** Pending
