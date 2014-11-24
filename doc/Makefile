midterm.pdf: midterm.md
	pandoc $^ \
		--standalone \
		--filter pandoc_exec \
		--to beamer \
		--template tpl.tex \
		--variable colortheme:seahorse \
		--output $@

clean:
	rm -f midterm.pdf
