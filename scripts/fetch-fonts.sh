#!/bin/sh
# Vendors the Gap theme's fonts into web/static/fonts: Saira (300–700) and
# Martian Mono (400–600), the variable-weight latin subset from Google Fonts,
# plus their SIL Open Font Licenses. The console serves them itself, so it never
# calls a font CDN. Only downloads what is missing, so offline builds keep working.
set -eu

dir=web/static/fonts
css_url='https://fonts.googleapis.com/css2?family=Saira:wght@300..700&family=Martian+Mono:wght@400..600&display=swap'
# Google Fonts serves woff2 only to browsers it recognises.
ua='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
mkdir -p "$dir"

# latin_url FAMILY: the woff2 URL of FAMILY's /* latin */ block in the css2 response.
latin_url() {
	printf '%s\n' "$css" | awk -v fam="'$1'" '
		/^\/\* latin \*\//   { latin = 1; next }
		/^\/\*/              { latin = 0 }
		latin && /font-family:/ { f = $0 }
		latin && /src: url\(/  { if (index(f, fam)) { match($0, /https:[^)]*/); print substr($0, RSTART, RLENGTH) }; latin = 0 }'
}

if [ ! -s "$dir/saira.woff2" ] || [ ! -s "$dir/martian-mono.woff2" ]; then
	echo "Downloading Saira and Martian Mono..."
	css=$(curl -fsSL -A "$ua" "$css_url")
	for pair in "Saira saira" "Martian Mono martian-mono"; do
		family=${pair% *}; file=${pair##* }
		url=$(latin_url "$family")
		[ -n "$url" ] || { echo "no latin woff2 for $family" >&2; exit 1; }
		curl -fsSL -o "$dir/$file.woff2" "$url"
	done
fi
[ -s "$dir/OFL-Saira.txt" ] || curl -fsSL -o "$dir/OFL-Saira.txt" https://raw.githubusercontent.com/google/fonts/main/ofl/saira/OFL.txt
[ -s "$dir/OFL-MartianMono.txt" ] || curl -fsSL -o "$dir/OFL-MartianMono.txt" https://raw.githubusercontent.com/google/fonts/main/ofl/martianmono/OFL.txt
