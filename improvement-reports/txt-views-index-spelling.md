# Suggest `txt_Ptrs[index]` spelling for txt_views.h placeholder views

- **Source:** match-base session 2026-11-01 (gildegold), worker 14
- **Area:** mk_txt_views.py / lint
- **Problem:** txt_views.h exposes views like `full_data_143b3f8` (`unsigned char[12]` at +0x1238) whose meaning is `txt_Ptrs[0x48e + kind*14]`; Q2 flags them as placeholders. Writing `txt_Ptrs[...]` compiles identically (shown as `=` aliases in asmdiff).
- **Proposal:** mk_txt_views.py comments each view with its `txt_Ptrs` index, or a lint hint suggests the `txt_Ptrs[index]` spelling.
- **Cost of not having it:** ~5 minutes to discover.
