"""`python -m secure_osint` e punto d'ingresso dei binari PyInstaller.

Usare questo file (e non cli.py) come script di PyInstaller: così `secure_osint.cli` viene importato
come modulo del pacchetto e la ricerca dei workflow accanto a `cli.py` punta a `secure_osint/workflows`.
"""

from secure_osint.cli import app

if __name__ == '__main__':
    app(prog_name='secure-osint')
