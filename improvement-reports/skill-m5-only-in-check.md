# Skill: say that M5 (declaration vs definition) is only reported by `dcp check` / `dcp lint`

- **Source:** match-base session 2026-11-02 (gildegold), worker 68
- **Area:** dcp-match-base skill (M7 / readability section)
- **Problem:** the skill says `dcp grade` and `dcp next` lint the changed units for M7, which reads as if they catch declaration problems in general. M5 is not reported by build or grade, only by `dcp check` / `dcp lint`; the worker learned this from a failed gate check.
- **Proposal:** one line in the skill: "after a signature change run `dcp check` before committing; build/grade do not report M5/M6". Superseded if build/grade start reporting M5 (../bug-reports/build-grade-miss-header-definition-mismatch.md).
- **Repro:** change a definition's signature without its header prototype, `dcp build`, `dcp grade NAME`, `dcp check` (gildegold, session ending 7193051).
- **Cost of not having it:** ~3 extra calls, twice this session.
- **Related:** skill-m7-vs-readable.md, stale-local-prototype-flag.md
