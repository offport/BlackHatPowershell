pandoc BlackHatPowershell.md -o  output.pdf \
--from markdown+yaml_metadata_block+raw_html \
--template eisvogel.latex \
--table-of-contents \
--toc-depth 3 \
--number-sections \
--top-level-division=chapter --listing -H style.tex --lua-filter colors.lua \

pdftk cover.pdf output.pdf cat output Report.pdf

