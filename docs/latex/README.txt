LATEX REPORT

The standalone, editable document is pq_multisig_report.tex. It requires no
external figures, bibliography database, or included source files. Upload this
file to Overleaf, or compile from the repository root with:

  tectonic --outdir output/pdf docs/latex/pq_multisig_report.tex

The verified PDF is output/pdf/pq_multisig_report.pdf.

For repeatable updates, edit report-template.tex, then run:

  python3 docs/latex/generate_report.py

The generator obtains measurements from benchmarks/latest.json and runtime
sizes from artifacts/*.json. It overwrites pq_multisig_report.tex. Edit the
template to retain changes across regeneration; edit the standalone .tex when
working independently of this repository.

The document distinguishes locally reproduced measurements, author-published
figures, algorithm substitutions, implementation optimizations, and setup costs.
It records wins against specified baselines. It does not claim the evidence
establishes superiority over every available implementation.
