midterm.pdf: midterm.md
	pandoc $^ \
		--standalone \
		--to beamer \
		--filter pandoc_exec \
		--template tpl.tex \
		--output $@

clean:
	rm -f midterm.pdf
