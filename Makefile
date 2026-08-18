PREFIX ?= /usr/local
APP_ID = io.github.catoblepa.signature-viewer

.PHONY: install install-lib install-bin install-data install-locales ui run

install: install-lib install-bin install-data install-locales

install-lib:
	install -d $(PREFIX)/lib/signature-viewer
	cp -r src/signature_viewer $(PREFIX)/lib/signature-viewer/
	install -m644 main.py $(PREFIX)/lib/signature-viewer/main.py
	find $(PREFIX)/lib/signature-viewer -name __pycache__ -type d -exec rm -rf {} +
	rm -rf $(PREFIX)/lib/signature-viewer/signature_viewer/ui/blueprints

install-bin:
	install -d $(PREFIX)/bin
	printf '#!/bin/sh\nexec python3 $(PREFIX)/lib/signature-viewer/main.py "$$@"\n' > $(PREFIX)/bin/signature-viewer
	chmod 755 $(PREFIX)/bin/signature-viewer

install-data:
	install -d $(PREFIX)/share/signature-viewer/ui
	python3 -c "import sys; from pathlib import Path; sys.path.insert(0, '$(PREFIX)/lib/signature-viewer'); from blueprintcompiler.main import BlueprintApp; [Path('$(PREFIX)/share/signature-viewer/ui', p.stem + '.ui').write_text(BlueprintApp()._compile(p.read_text())[0]) for p in Path('src/signature_viewer/ui/blueprints').glob('*.blp')]"
	install -Dm644 data/icons/hicolor/scalable/apps/$(APP_ID).svg $(PREFIX)/share/icons/hicolor/scalable/apps/$(APP_ID).svg
	install -Dm644 data/$(APP_ID).desktop $(PREFIX)/share/applications/$(APP_ID).desktop
	install -Dm644 data/$(APP_ID).metainfo.xml $(PREFIX)/share/metainfo/$(APP_ID).metainfo.xml

install-locales:
	for po_file in locale/*/LC_MESSAGES/*.po; do \
		lang=$$(basename $$(dirname $$(dirname "$$po_file"))); \
		mkdir -p "$(PREFIX)/share/locale/$$lang/LC_MESSAGES"; \
		msgfmt -o "$(PREFIX)/share/locale/$$lang/LC_MESSAGES/$(APP_ID).mo" "$$po_file"; \
	done

ui:
	mkdir -p build/ui
	blueprint-compiler batch-compile build/ui src/signature_viewer/ui/blueprints $(wildcard src/signature_viewer/ui/blueprints/*.blp)

run:
	python3 main.py