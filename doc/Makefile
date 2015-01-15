all: midterm.pdf final.pdf

midterm.pdf: midterm.md
	pandoc $^ \
		--standalone \
		--to beamer \
		--filter pandoc_exec \
		--template tpl.tex \
		--output $@

final.pdf: final.md
	pandoc $^ \
		--standalone \
		--to beamer \
		--filter pandoc_exec \
		--template tpl.tex \
		--slide-level=2 \
		--output $@

clean:
	rm -f midterm.pdf final.pdf
