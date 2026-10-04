"""Grafo investigativo interattivo (pyvis / vis-network), 100% locale.

Il grafo si costruisce SOLO dal dizionario `correlations` del report (`ReportGenerator.correlations()`),
già redatto con lo stesso PrivacyGuard: nessuna chiamata di rete, e il grafo non mostra mai nulla
che il report nasconda (email/IP `[REDACTED]` salvo `--keep-network`).

Cosa mostra:
- il target al centro (stella rossa);
- un nodo per piattaforma dall'esito della ricerca username: trovato (blu, arco pieno "username
  found on"), match possibile (ricerca per nome, arco tratteggiato), verifica manuale necessaria
  (giallo: login richiesto, bloccato o errore), non trovato (grigio, nascosto di default);
- domini/email (verde) e infrastruttura (arancione), collegati con la relazione che i dati
  dimostrano ("resolves to", "nameserver", "mail server", "uses domain") o, se non c'è, "observed with".

Onestà del modello: uno username esistente su una piattaforma NON prova che l'account sia del target
(l'arco dice "username found on", non "owns"). Lo spessore degli archi codifica la certezza, non una
"forza" inventata. Non esistono timestamp per singolo controllo: il tooltip riporta l'ora dell'esecuzione.

Sicurezza del file HTML (trappole di pyvis gestite qui):
- anche con `cdn_resources='in_line'` il template carica Bootstrap da cdn.jsdelivr.net: quei tag
  vengono rimossi e, se resta un URL esterno, l'export fallisce invece di scrivere un file che
  "telefona a casa";
- `{{heading}}` nel template non è escapato: non ci mettiamo mai dati dell'utente. I dati dei nodi
  passano per `tojson` di Jinja (escapa `<`/`>`). Il JS iniettato (doppio clic per aprire il profilo)
  è statico e apre solo URL https.

Il modello (nodi/archi/filtri) è puro Python, testabile senza pyvis.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

from secure_osint.core.privacy import PrivacyGuard
from secure_osint.core.reporter import _write_private

if TYPE_CHECKING:  # pragma: no cover
    from pyvis.network import Network

GRAPH_MISSING_MSG = "Graph generation requires: pip install 'secure-osint[graph]'"

BACKGROUND = '#0b0d12'
FONT_COLOR = '#ffffff'

# Categorie filtrabili (GUI) e default: i "non trovati" non aggiungono valore, nascosti di default.
FILTERS = ('found', 'manual', 'not_found', 'infrastructure', 'domains', 'pivots')
DEFAULT_FILTERS: FrozenSet[str] = frozenset({'found', 'manual', 'infrastructure', 'domains', 'pivots'})

# Tree layout: una colonna per categoria (ordine di FILTERS), il target sopra, al centro. Le
# coordinate sono definitive (il renderer disattiva la fisica), quindi il layout è deterministico
# e testabile in puro Python.
_COLUMN_WIDTH = 220
_ROW_HEIGHT = 90

# Etichetta di tipo mostrata sulla card (renderer canvas, in network_from_model).
_CARD_TYPE_LABEL: Dict[str, str] = {
    'found': 'Platform',
    'manual': 'Manual Check',
    'not_found': 'Platform',
    'domains': 'Domain / Email',
    'infrastructure': 'Infrastructure',
    'pivots': 'Suggested Pivot',
}

# Stile per tipo di nodo: colore, forma, dimensione (importanza).
STYLES: Dict[str, Dict[str, Any]] = {
    'target': {'color': '#e5484d', 'shape': 'star', 'size': 44},
    'found': {'color': '#3e8ef7', 'shape': 'dot', 'size': 24},
    'low': {'color': '#94a3b8', 'shape': 'dot', 'size': 18},
    'manual': {'color': '#f5c451', 'shape': 'diamond', 'size': 20},
    'not_found': {'color': '#6b7280', 'shape': 'dot', 'size': 11},
    'username': {'color': '#3e8ef7', 'shape': 'dot', 'size': 18},
    'domain': {'color': '#30a46c', 'shape': 'square', 'size': 18},
    'infrastructure': {'color': '#f5a524', 'shape': 'triangle', 'size': 15},
    # C5 evidence: phone numbers, image GPS fix and camera, crypto wallets.
    'phone': {'color': '#2dd4bf', 'shape': 'square', 'size': 16},
    'location': {'color': '#e879f9', 'shape': 'diamond', 'size': 16},
    'device': {'color': '#a78bfa', 'shape': 'square', 'size': 16},
    'wallet': {'color': '#facc15', 'shape': 'square', 'size': 16},
    # Pivot suggerito: grigio, bordo tratteggiato. È solo un suggerimento, mai eseguito.
    'pivot': {
        'color': {'background': '#1f2937', 'border': '#9ca3af'},
        'shape': 'box',
        'borderWidth': 2,
        'shapeProperties': {'borderDashes': [5, 5]},
    },
}

# Default style of a node by filter category (for expander nodes, which carry no style of their own).
_CATEGORY_STYLE: Dict[str, str] = {
    'found': 'found',
    'manual': 'manual',
    'not_found': 'not_found',
    'infrastructure': 'infrastructure',
    'domains': 'domain',
    'pivots': 'pivot',
}

# Archi: stile = certezza. Per gli account trovati dipende dalla confidenza della fonte:
# HIGH pieno e spesso, MEDIUM tratteggiato, LOW sottile, grigio e punteggiato.
_FOUND_EDGES: Dict[str, Dict[str, Any]] = {
    'HIGH': {'label': 'username found on', 'color': '#3e8ef7', 'width': 3, 'dashes': False},
    'MEDIUM': {'label': 'username found on', 'color': '#3e8ef7', 'width': 2, 'dashes': [8, 6]},
    'LOW': {'label': 'low-confidence match', 'color': '#94a3b8', 'width': 1, 'dashes': [2, 5]},
}
_ACCOUNT_EDGES: Dict[str, Dict[str, Any]] = {
    'manual': {'label': 'needs manual verification', 'color': '#f5c451', 'width': 1.5, 'dashes': True},
    'not_found': {'label': 'not found on', 'color': '#4b5563', 'width': 1, 'dashes': [2, 6]},
}
_CONFIDENCE_TEXT = {
    'HIGH': 'HIGH (public API with a clear answer)',
    'MEDIUM': 'MEDIUM (web page, checked against a username that does not exist)',
    'LOW': 'LOW: verify manually',
    'MANUAL': 'MANUAL: not checked automatically',
}
_STATUS_TEXT = {
    'found': 'username exists',
    'manual': 'could not be checked automatically: verify manually',
    'not_found': 'not found',
}
_PROFILE_LINES = (
    ('display_name', 'Name'),
    ('bio', 'Bio'),
    ('created_at', 'Created'),
    ('packages', 'Packages'),
    ('avatar_url', 'Avatar (URL only, not downloaded)'),
)

# Tag <link>/<script> che puntano a un URL http(s): vanno tolti per restare offline.
# Any innerHTML assignment fed from vis node/edge data (title, label): fail closed if pyvis adds one.
_INNER_HTML_FROM_DATA = re.compile(r'\.innerHTML\s*=\s*[^;\n]*(?:nodeData|edgeData|\.title\b|\.label\b)')
_EXTERNAL_TAG = re.compile(
    r'<(?:link|script)\b[^>]*\b(?:href|src)\s*=\s*["\']https?://[^"\']*["\'][^>]*>(?:\s*</script>)?',
    re.IGNORECASE,
)

# --- external-resource guard ---
# Any of these in the final page means opening it could contact a third party: the export fails
# instead of writing it. The checks are split by where they look:
# - MARKUP (the page with the BODIES of <script> blocks removed): resource attributes, srcset,
#   CSS @import / url(), embedding tags, meta refresh, resource hints, inline JS handlers.
# - SCRIPTS (the bodies of <script> blocks): network APIs. Node data reaches the page ONLY as
#   tojson-escaped, double-quoted JSON strings inside a script, so the API-name check runs with
#   double-quoted string literals blanked: a bio that merely mentions "fetch(" stays inert text.
#   Patterns that need a literal URL argument (a quote right before ``//``) run on the unmasked
#   scripts: inside a JSON string that quote would be escaped as ``\"`` and cannot match.
_REMOTE = r'(?:(?:https?|wss?|ftp):)?//'
_MARKUP_CHECKS: Tuple[Tuple[str, 're.Pattern[str]'], ...] = (
    (
        'resource attribute',
        re.compile(
            r'\b(?:href|src|action|formaction|data|poster|background|xlink:href|ping|manifest|codebase|cite|'
            r'longdesc|lowsrc|dynsrc|archive|profile|usemap)\s*=\s*["\']?\s*' + _REMOTE,
            re.IGNORECASE,
        ),
    ),
    ('srcset', re.compile(r'\b(?:image)?srcset\s*=\s*(?:"[^"]*|\'[^\']*|[^\s>]*)' + _REMOTE, re.IGNORECASE)),
    ('css @import', re.compile(r'@import\b', re.IGNORECASE)),
    ('css url()', re.compile(r'url\(\s*["\']?\s*' + _REMOTE, re.IGNORECASE)),
    ('embedding tag', re.compile(r'<(?:iframe|frame|frameset|object|embed|applet|portal|base)\b', re.IGNORECASE)),
    ('meta refresh', re.compile(r'<meta\b[^>]*http-equiv\s*=\s*["\']?\s*refresh', re.IGNORECASE)),
    (
        'resource hint',
        re.compile(
            r'<link\b[^>]*\brel\s*=\s*["\']?[^"\'>]*\b(?:dns-prefetch|preconnect|prefetch|prerender|preload|modulepreload)\b',
            re.IGNORECASE,
        ),
    ),
)
_NETWORK_API = re.compile(
    r'\b(?:XMLHttpRequest|WebSocket|EventSource|importScripts|sendBeacon|RTCPeerConnection|WebTransport)\b'
    r'|\b(?:fetch|import)\s*\('
)
_SCRIPT_URL_CHECKS: Tuple[Tuple[str, 're.Pattern[str]'], ...] = (
    (
        'remote URL assigned in script',
        re.compile(r'\.(?:src|href|action|data|srcset)\s*=\s*["\'`]\s*' + _REMOTE, re.IGNORECASE),
    ),
    (
        'remote URL set as attribute in script',
        re.compile(
            r'setAttribute\s*\(\s*["\'`](?:src|href|srcset|action|data)["\'`]\s*,\s*["\'`]\s*' + _REMOTE,
            re.IGNORECASE,
        ),
    ),
    ('css url() in script', re.compile(r'url\(\s*["\'`]\s*' + _REMOTE, re.IGNORECASE)),
)
_SCRIPT_BLOCK = re.compile(r'(<script\b[^>]*>)(.*?)(</script\s*>)', re.IGNORECASE | re.DOTALL)
_JS_DOUBLE_QUOTED = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_SAFE_STEM = re.compile(r'[^A-Za-z0-9._-]+')
_SAFE_URL = re.compile(r'^https://[^\s"\'<>]+$')

# Legenda e comportamento statici (nessun dato dell'utente) iniettati nella pagina esportata.
# La legenda sta SOTTO il canvas (non sovrapposta): non può mai coprire un nodo.
_LEGEND = """
<style>html,body{background:#0b0d12;margin:0}
div.vis-tooltip{background:#1b1f2a;color:#e6e8ee;border:1px solid #3a4150;border-radius:6px;
font:12px/1.5 system-ui,sans-serif;white-space:pre;padding:8px 10px}</style>
<div style="clear:both;margin:8px 12px;padding:8px 12px;border-radius:8px;
background:#141821;color:#e6e8ee;font:12px/1.5 system-ui,sans-serif">
<b>Investigation graph</b><br>
<span style="color:#e5484d">&#9733;</span> Target &nbsp;
<span style="color:#3e8ef7">&#9679;</span> Username found (solid = high, dashed = medium confidence) &nbsp;
<span style="color:#94a3b8">&#9679;</span> Low confidence &nbsp;
<span style="color:#f5c451">&#9670;</span> Manual check &nbsp;
<span style="color:#6b7280">&#9679;</span> Not found &nbsp;
<span style="color:#30a46c">&#9632;</span> Domain / email &nbsp;
<span style="color:#f5a524">&#9650;</span> Infrastructure &nbsp;
<span style="color:#2dd4bf">&#9632;</span> Phone &nbsp;
<span style="color:#e879f9">&#9670;</span> Image location &nbsp;
<span style="color:#a78bfa">&#9632;</span> Camera &nbsp;
<span style="color:#facc15">&#9632;</span> Wallet &nbsp;
<span style="color:#9ca3af">&#9633;</span> Suggested pivot (never run automatically)<br>
<span style="opacity:.75">Click a card to see its details, double-click a platform to open its profile.
A username found on a platform does not prove the target owns that account; "observed with" means
co-occurrence in this investigation, not a verified identity.</span>
</div>
"""

# Card canvas renderer + side inspector: nessuna dipendenza esterna (niente font/icone da CDN),
# solo canvas 2D e DOM standard. L'inspector usa SEMPRE `textContent`, mai `innerHTML`: il testo
# mostrato (titolo del nodo, con profilo/URL) è già redatto da PrivacyGuard ma può comunque
# contenere caratteri arbitrari (es. una bio con `<script>`), quindi va inserito come testo puro,
# mai interpretato come markup.
_CARD_JS = r"""
<script>
(function () {
  var CARD_W = 168, CARD_H = 64;
  var CONFIDENCE_FILL = {HIGH: '#1d4933', MEDIUM: '#4a3b12', LOW: '#3a3f4a', MANUAL: '#4a3612'};
  var CONFIDENCE_TEXT = {HIGH: '#7cffb2', MEDIUM: '#ffd37c', LOW: '#c7cdd6', MANUAL: '#ffd37c'};

  function roundedRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  function drawIcon(ctx, shape, cx, cy, color) {
    ctx.fillStyle = color;
    ctx.strokeStyle = color;
    if (shape === 'square') {
      ctx.fillRect(cx - 5, cy - 5, 10, 10);
    } else if (shape === 'triangle') {
      ctx.beginPath();
      ctx.moveTo(cx, cy - 6); ctx.lineTo(cx + 6, cy + 5); ctx.lineTo(cx - 6, cy + 5);
      ctx.closePath(); ctx.fill();
    } else if (shape === 'diamond') {
      ctx.beginPath();
      ctx.moveTo(cx, cy - 6); ctx.lineTo(cx + 6, cy); ctx.lineTo(cx, cy + 6); ctx.lineTo(cx - 6, cy);
      ctx.closePath(); ctx.fill();
    } else if (shape === 'box') {
      ctx.setLineDash([3, 2]);
      ctx.strokeRect(cx - 6, cy - 6, 12, 12);
      ctx.setLineDash([]);
    } else {
      ctx.beginPath();
      ctx.arc(cx, cy, 5, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function fitText(ctx, text, maxWidth) {
    text = String(text || '');
    while (ctx.measureText(text).width > maxWidth && text.length > 1) {
      text = text.slice(0, -2) + '…';
    }
    return text;
  }

  function cardRenderer(arg) {
    var ctx = arg.ctx, x = arg.x, y = arg.y, label = arg.label;
    var node = nodes.get(arg.id) || {};
    var left = x - CARD_W / 2, top = y - CARD_H / 2;
    return {
      drawNode: function () {
        ctx.save();
        roundedRect(ctx, left, top, CARD_W, CARD_H, 10);
        ctx.fillStyle = '#141821';
        ctx.fill();
        ctx.lineWidth = (arg.state && (arg.state.selected || arg.state.hover)) ? 3 : 2;
        ctx.strokeStyle = node.cardColor || '#94a3b8';
        ctx.stroke();

        drawIcon(ctx, node.cardIcon, left + 16, top + 16, node.cardColor || '#94a3b8');

        ctx.fillStyle = '#9aa4b2';
        ctx.font = '10px system-ui, sans-serif';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillText(fitText(ctx, String(node.cardType || '').toUpperCase(), CARD_W - 40), left + 28, top + 16);

        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 13px system-ui, sans-serif';
        ctx.fillText(fitText(ctx, label, CARD_W - 24), left + 12, top + 40);

        if (node.cardConfidence) {
          ctx.font = '9px system-ui, sans-serif';
          var badge = node.cardConfidence;
          var bw = ctx.measureText(badge).width + 12;
          var bx = left + CARD_W - bw - 8, by = top + CARD_H - 22;
          ctx.fillStyle = CONFIDENCE_FILL[badge] || '#2a2f3a';
          roundedRect(ctx, bx, by, bw, 16, 6);
          ctx.fill();
          ctx.fillStyle = CONFIDENCE_TEXT[badge] || '#c7cdd6';
          ctx.textAlign = 'center';
          ctx.fillText(badge, bx + bw / 2, by + 8);
        }
        ctx.restore();
      },
      nodeDimensions: {width: CARD_W, height: CARD_H}
    };
  }

  function ensureInspector() {
    var panel = document.getElementById('card-inspector');
    if (panel) { return panel; }
    var container = document.getElementById('mynetwork');
    panel = document.createElement('div');
    panel.id = 'card-inspector';
    panel.style.cssText = 'position:absolute;top:10px;right:10px;width:280px;' +
      'max-height:calc(100% - 20px);overflow:auto;background:#141821;color:#e6e8ee;' +
      'border:1px solid #3a4150;border-radius:8px;padding:10px 12px;' +
      'font:12px/1.5 system-ui,sans-serif;white-space:pre-wrap;z-index:10';
    var heading = document.createElement('div');
    heading.id = 'card-inspector-heading';
    heading.style.cssText = 'font-weight:bold;margin-bottom:6px;color:#ffffff';
    var body = document.createElement('div');
    body.id = 'card-inspector-body';
    body.textContent = 'Click a card to see its details.';
    panel.appendChild(heading);
    panel.appendChild(body);
    container.appendChild(panel);
    return panel;
  }

  function showInspector(node) {
    ensureInspector();
    // textContent, mai innerHTML: node.label/node.title sono testo, non markup fidato.
    document.getElementById('card-inspector-heading').textContent = String(node.label || node.id || '');
    document.getElementById('card-inspector-body').textContent = String(node.title || 'No further details.');
  }

  function clearInspector() {
    ensureInspector();
    document.getElementById('card-inspector-heading').textContent = '';
    document.getElementById('card-inspector-body').textContent = 'Click a card to see its details.';
  }

  function hook() {
    if (typeof network === 'undefined' || typeof nodes === 'undefined') { return setTimeout(hook, 100); }
    nodes.get().forEach(function (n) {
      if (n.card) { nodes.update({id: n.id, shape: 'custom', ctxRenderer: cardRenderer}); }
    });
    ensureInspector();
    network.fit({animation: false});
    // Ridondante ma innocuo: nel raro caso la fisica fosse riattivata in futuro, la vista resta corretta.
    network.once('stabilizationIterationsDone', function () { network.fit({animation: false}); });
    setTimeout(function () { network.fit({animation: false}); }, 2500);
    network.on('click', function (params) {
      if (!params.nodes.length) { clearInspector(); return; }
      var node = nodes.get(params.nodes[0]);
      if (node) { showInspector(node); }
    });
    network.on('doubleClick', function (params) {
      if (!params.nodes.length) { return; }
      var node = nodes.get(params.nodes[0]);
      if (node && typeof node.url === 'string' && /^https:\/\/[^\s"'<>]+$/.test(node.url)) {
        window.open(node.url, '_blank', 'noopener,noreferrer');
      }
    });
  }
  hook();
})();
</script>
"""

# --- click-to-expand (predisposizione) ---
# Un "expander" riceve il `ref` di un nodo (es. {'kind': 'account', 'platform': 'github', ...}) e
# restituisce nuovi nodi/archi (es. repository e gist). Qui c'è solo il contratto: un expander futuro
# fa chiamate di rete, quindi deve passare per l'ethical gate e il SafeHttpClient come ogni fonte.
Expander = Callable[[Dict[str, Any]], Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]]
EXPANDERS: Dict[str, Expander] = {}


def register_expander(platform: str) -> Callable[[Expander], Expander]:
    """Register a function that expands the account node of ``platform`` into more nodes/edges."""

    def decorator(func: Expander) -> Expander:
        EXPANDERS[platform] = func
        return func

    return decorator


def _text(value: Any, guard: PrivacyGuard, limit: int = 300) -> str:
    text = ' '.join(str(value if value is not None else '').split())[:limit]
    return str(guard.redact(text))


def _expanded_node(platform: str, raw: Any, guard: PrivacyGuard) -> Dict[str, Any]:
    """An expander node reduced to known keys, redacted, styled and with a valid filter category."""
    if not isinstance(raw, dict) or not isinstance(raw.get('id'), str) or not raw['id'].strip():
        raise ValueError(f'Expander for {platform!r} returned a node without a string id: {raw!r:.80}')
    category = raw.get('category')
    if category == 'target':
        raise ValueError(f'Expander for {platform!r} tried to add a second target node')
    if category not in FILTERS:
        category = 'found'  # an expander expands an account: its items are found on that platform
    node_id = raw['id'].strip()
    label = _text(raw.get('label') or node_id, guard, 120)
    node: Dict[str, Any] = {
        'id': node_id,
        'label': label,
        'title': _text(raw.get('title') or label, guard),
        'category': category,
        **STYLES[_CATEGORY_STYLE[category]],
    }
    url = raw.get('url')
    if isinstance(url, str) and _SAFE_URL.match(url):
        node['url'] = _text(url, guard)
    return node


def _expanded_edge(platform: str, raw: Any, guard: PrivacyGuard) -> Dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get('from'), str) or not isinstance(raw.get('to'), str):
        raise ValueError(f'Expander for {platform!r} returned an edge without string from/to: {raw!r:.80}')
    label = _text(raw.get('label') or 'related to', guard, 60)
    return {'from': raw['from'], 'to': raw['to'], 'label': label, 'title': _text(raw.get('title') or label, guard)}


def expand_node(model: Dict[str, Any], node_id: str, guard: Optional[PrivacyGuard] = None) -> Dict[str, Any]:
    """Return a new model with ``node_id`` expanded by its platform's registered expander.

    The expander's output is untrusted (it comes from network data): every node is reduced to the
    keys the renderer knows (``id``, ``label``, ``title``, ``category``, an https ``url``), its text
    is redacted with ``guard`` (default: everything redacted) and an unknown category becomes
    ``found``. Edges keep ``from``/``to``/``label``/``title``; an edge to an unknown node is dropped.

    Raises:
        LookupError: If the node does not exist or no expander is registered for it.
        ValueError: If the expander output is not ``(nodes, edges)`` lists of well-formed dicts.
    """
    node = next((n for n in model['nodes'] if n.get('id') == node_id), None)
    ref = (node or {}).get('ref') or {}
    platform = str(ref.get('platform', ''))
    expander = EXPANDERS.get(platform)
    if node is None or expander is None:
        raise LookupError(f'No expander available for node {node_id!r}')
    result = expander(ref)
    if not (isinstance(result, (tuple, list)) and len(result) == 2 and all(isinstance(r, list) for r in result)):
        raise ValueError(f'Expander for {platform!r} must return (nodes, edges) lists, got {type(result).__name__}')
    guard = guard or PrivacyGuard()
    new_nodes = [_expanded_node(platform, raw, guard) for raw in result[0]]
    new_edges = [_expanded_edge(platform, raw, guard) for raw in result[1]]
    known = {n.get('id') for n in model['nodes']}
    nodes = list(model['nodes'])
    for item in new_nodes:
        if item['id'] not in known:
            known.add(item['id'])
            nodes.append(item)
    edges = list(model['edges']) + [e for e in new_edges if e['from'] in known and e['to'] in known]
    _layout_tree(nodes)
    return {**model, 'nodes': nodes, 'edges': edges}


# --- model ---


def _require_pyvis() -> Any:
    try:
        from pyvis.network import Network
    except ImportError as e:
        raise RuntimeError(GRAPH_MISSING_MSG) from e
    return Network


def ensure_graph_support() -> None:
    """Raise RuntimeError with the install hint if the optional pyvis extra is missing."""
    _require_pyvis()


_Clean = Callable[[Any], str]

# Entity buckets of the correlations: (bucket, style, filter category, kind shown in the tooltip,
# hint shown when the value is redacted). C5 evidence (phones, image GPS/camera, wallets) goes in
# the 'domains' column: the GUI filter list is fixed, and these are identifiers like an email.
_ENTITY_BUCKETS: Tuple[Tuple[str, str, str, str, str], ...] = (
    ('usernames', 'username', 'found', 'username', ''),
    ('emails', 'domain', 'domains', 'email', 'emails are always redacted'),
    ('domains', 'domain', 'domains', 'domain', ''),
    ('infrastructure', 'infrastructure', 'infrastructure', 'infrastructure', 'IPs are shown with --keep-network'),
    ('phones', 'phone', 'domains', 'phone', 'phone numbers are shown with --keep-network'),
    ('locations', 'location', 'domains', 'location', 'image GPS coordinates are shown with --keep-location'),
    ('devices', 'device', 'domains', 'device', 'camera serial numbers are shown with --keep-device'),
    ('wallets', 'wallet', 'domains', 'wallet', 'wallet addresses are shown with --keep-crypto'),
)


def _account_label(status: str, name: str, username: str, low: bool) -> str:
    if status == 'manual':
        return f'{name} (manual check required)'
    if status == 'not_found':
        return f'{name}: not found'
    return (f'{name}: {username}' if username else name) + (' (low confidence)' if low else '')


def _account_node(
    account: Dict[str, Any], clean: _Clean, checked_at: str
) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], str]]:
    """``(node, edge from the target, username)`` for one per-platform outcome, or None to skip it."""
    status = account.get('status')
    confidence = str(account.get('confidence') or '')
    if status == 'possible':  # older format: a name match is a low-confidence match
        status, confidence = 'found', 'LOW'
    if status not in ('found', 'manual', 'not_found'):
        return None
    if status == 'found' and confidence not in _FOUND_EDGES:
        confidence = 'MEDIUM'
    platform, name = clean(account.get('platform')), clean(account.get('label') or account.get('platform'))
    username, url, note = clean(account.get('username')), clean(account.get('url')), clean(account.get('note'))
    low = status == 'found' and confidence == 'LOW'
    title = [name, f'Status: {_STATUS_TEXT[status]}']
    if status == 'found':
        title.append(f'Confidence: {_CONFIDENCE_TEXT[confidence]}')
    raw_profile = account.get('profile')
    profile: Dict[str, Any] = raw_profile if isinstance(raw_profile, dict) else {}
    for key, caption in _PROFILE_LINES:
        if profile.get(key) not in (None, ''):
            value = clean(profile[key])
            title.append(f'{caption}: {value[:120] + "…" if len(value) > 120 else value}')
    if url:
        title.append(f'URL: {url}')
    if note:
        title.append(f'Note: {note}')
    if low:
        title.append('Low confidence: verify manually')
    title.append(f'Checked during run: {checked_at}')
    node: Dict[str, Any] = {
        'id': f'account:{platform}',
        'label': _account_label(status, name, username, low),
        'category': status,
        'status': status,
        'confidence': confidence if status == 'found' else ('MANUAL' if status == 'manual' else ''),
        'ref': {'kind': 'account', 'platform': platform, 'username': username, 'url': url},
        **STYLES['low' if low else status],
    }
    if _SAFE_URL.match(url) and status != 'not_found':
        node['url'] = url
        title.append('Double-click to open the profile')
    if platform in EXPANDERS:
        node['expandable'] = True
    node['title'] = '\n'.join(title)
    edge_style = _FOUND_EDGES[confidence] if status == 'found' else _ACCOUNT_EDGES[status]
    edge_title = 'Low confidence: verify manually' if low else edge_style['label']
    edge = {'from': 'target', 'to': node['id'], 'title': edge_title, **edge_style}
    return node, edge, username


def _relation_index(correlations: Dict[str, Any], clean: _Clean, target: str) -> Dict[Tuple[Optional[str], str], str]:
    """Relations from the target, keyed by ``(bucket, label)``.

    Two entities of different buckets (e.g. an email and an IP) can redact to the same placeholder
    but remain distinct relations: keying by label alone would collapse them, letting one entity
    inherit another's relation (an email that "resolves to" as if it were the IP). The reporter
    (``ReportGenerator._redact_correlations``) already resolves each relation per bucket on the raw
    pre-redaction value; the same bucket is honoured here so that correctness is not lost again by
    matching on an already reduced string.
    """
    relations: Dict[Tuple[Optional[str], str], str] = {}
    for relation in correlations.get('relations') or []:
        if clean(relation.get('from')) == target:
            relations.setdefault((relation.get('bucket'), clean(relation.get('to'))), clean(relation.get('type')))
    return relations


def _entity_elements(
    correlations: Dict[str, Any], clean: _Clean, labels: set, seen: set, relations: Dict[Tuple[Optional[str], str], str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Nodes and edges for the entity buckets. An edge without a demonstrated relation says only
    'observed with': co-occurrence in the same investigation, not a verified identity."""
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for bucket, style, category, kind, hint in _ENTITY_BUCKETS:
        for value in correlations.get(bucket) or []:
            label = clean(value)
            node_id = f'{bucket}:{label}'
            if not label or label in labels or node_id in seen:  # no duplicates, no self-loops
                continue
            seen.add(node_id)
            if '[REDACTED' in label:
                tooltip = f'{kind}: value redacted' + (f' ({hint})' if hint else '')
            else:
                tooltip = f'{kind}: {label}'
            node = {'id': node_id, 'label': label, 'title': tooltip, 'category': category, **STYLES[style]}
            if category == 'domains' and kind not in ('email', 'domain'):
                node['cardType'] = kind.title()
            nodes.append(node)
            relation = relations.get((bucket, label))
            edges.append(
                {
                    'from': 'target',
                    'to': node_id,
                    'label': relation or 'observed with',
                    'title': relation or 'observed in the same investigation (co-occurrence, not verified identity)',
                    'color': STYLES[style]['color'] if relation else '#4b5563',
                    'width': 2 if relation else 1,
                    'dashes': False if relation else [4, 4],
                }
            )
    return nodes, edges


def _pivot_elements(
    correlations: Dict[str, Any], clean: _Clean, seen: set
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Suggested pivots: distinct nodes linked to the target. Suggestions only, never run."""
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    for pivot in correlations.get('suggested_pivots') or []:
        text = clean(pivot)
        node_id = f'pivot:{text}'
        if not text or node_id in seen:
            continue
        seen.add(node_id)
        nodes.append(
            {
                'id': node_id,
                'label': f'Suggested Pivot: {text}',
                'title': 'Suggested pivot: not run automatically. Investigate it separately, only with a lawful basis.',
                'category': 'pivots',
                'font': {'color': '#d1d5db'},
                **STYLES['pivot'],
            }
        )
        edges.append(
            {
                'from': 'target',
                'to': node_id,
                'label': 'suggested pivot',
                'title': 'suggested pivot (not run)',
                'color': '#6b7280',
                'width': 1,
                'dashes': [3, 5],
            }
        )
    return nodes, edges


def graph_model(
    correlations: Dict[str, Any],
    redacted: bool = True,
    guard: Optional[PrivacyGuard] = None,
    checked_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Full (unfiltered) investigation graph as plain dicts: ``{'nodes', 'edges', 'checked_at'}``.

    Args:
        correlations: A report's ``correlations`` (from ``ReportGenerator.correlations()``).
        redacted: Apply ``guard`` to every string. Keep True: with report correlations it is
            idempotent, and it protects against raw values passed by mistake.
        guard: The run's PrivacyGuard (so ``--keep-network`` matches the report).
        checked_at: When the run happened (per-check times are not recorded); defaults to now (UTC).

    Returns:
        Every node carries a filter ``category`` (one of ``FILTERS``, or ``target``).
    """
    active_guard = guard or PrivacyGuard()
    checked_at = checked_at or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    def clean(value: Any) -> str:
        text = str(value if value is not None else '').strip()
        return str(active_guard.redact(text)) if redacted else text

    target = clean(correlations.get('primary_target')) or '(no target)'
    nodes: List[Dict[str, Any]] = [
        {
            'id': 'target',
            'label': target,
            'title': f'Primary target: {target}',
            'category': 'target',
            **STYLES['target'],
        }
    ]
    edges: List[Dict[str, Any]] = []
    labels = {target}
    for account in correlations.get('accounts') or []:
        built = _account_node(account, clean, checked_at)
        if built is not None:
            node, edge, username = built
            nodes.append(node)
            edges.append(edge)
            labels.add(username)
    seen: set = set()
    relations = _relation_index(correlations, clean, target)
    for extra_nodes, extra_edges in (
        _entity_elements(correlations, clean, labels, seen, relations),
        _pivot_elements(correlations, clean, seen),
    ):
        nodes.extend(extra_nodes)
        edges.extend(extra_edges)
    _layout_tree(nodes)
    return {'nodes': nodes, 'edges': edges, 'checked_at': checked_at}


def _layout_tree(nodes: List[Dict[str, Any]]) -> None:
    """Assign a deterministic ``(x, y)`` to every non-target node, in place.

    One column per category (``FILTERS`` order), centered under the target; nodes stack top to
    bottom within their column in insertion order. Pure Python: the tree layout is the final
    on-screen position, not a starting point for a physics simulation (see ``network_from_model``).
    """
    columns: Dict[str, List[Dict[str, Any]]] = {category: [] for category in FILTERS}
    for node in nodes:
        category = node.get('category')
        bucket = columns.get(category) if isinstance(category, str) else None
        if bucket is not None:
            bucket.append(node)
    mid = (len(FILTERS) - 1) / 2
    for col_index, category in enumerate(FILTERS):
        x = round((col_index - mid) * _COLUMN_WIDTH)
        for row_index, node in enumerate(columns[category]):
            node['x'] = x
            node['y'] = _ROW_HEIGHT * (row_index + 1)


def filter_model(model: Dict[str, Any], filters: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Keep the target plus nodes whose category is in ``filters`` (default: ``DEFAULT_FILTERS``)."""
    active = DEFAULT_FILTERS if filters is None else frozenset(filters)
    nodes = [n for n in model['nodes'] if n.get('category') == 'target' or n.get('category') in active]
    kept = {n.get('id') for n in nodes}
    edges = [e for e in model['edges'] if e.get('from') in kept and e.get('to') in kept]
    return {**model, 'nodes': nodes, 'edges': edges}


def graph_elements(
    correlations: Dict[str, Any],
    redacted: bool = True,
    guard: Optional[PrivacyGuard] = None,
    filters: Optional[Iterable[str]] = None,
    checked_at: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Filtered ``(nodes, edges)`` for the correlations (pure Python, no pyvis needed)."""
    model = filter_model(graph_model(correlations, redacted=redacted, guard=guard, checked_at=checked_at), filters)
    return model['nodes'], model['edges']


# --- rendering ---


def network_from_model(model: Dict[str, Any]) -> 'Network':
    """A dark-themed pyvis Network with a deterministic tree layout for an (already filtered) model.

    The target is fixed at the top-center; every other node keeps the ``(x, y)`` that
    ``graph_model`` assigned it (one column per category). Physics is off: those coordinates are
    the final layout, not a seed for a simulation. Entity nodes are marked ``card=True`` so the
    injected client-side script (see ``_CARD_JS``) upgrades them to a canvas-drawn card; pyvis only
    ships their original shape/color as the card's icon.
    """
    network_cls = _require_pyvis()
    net = network_cls(
        height='720px',
        width='100%',
        bgcolor=BACKGROUND,
        font_color=FONT_COLOR,
        directed=True,
        cdn_resources='in_line',  # vis-network incluso nel file: nessun CDN per il grafo
    )
    for node in model['nodes']:
        options = {k: v for k, v in node.items() if k not in ('id', 'category')}
        if node['category'] == 'target':
            options.update(x=0, y=0, fixed=True)
        else:
            raw_color = options.get('color', '#94a3b8')
            icon_color = raw_color if isinstance(raw_color, str) else raw_color.get('border', '#94a3b8')
            options['card'] = True
            options['cardIcon'] = options.get('shape', 'dot')
            options['cardColor'] = icon_color
            options['cardType'] = options.get('cardType') or _CARD_TYPE_LABEL.get(
                node['category'], node['category'].replace('_', ' ').title()
            )
            options['cardConfidence'] = node.get('confidence') or ''
        font = {'color': FONT_COLOR, 'size': 15, **options.pop('font', {})}
        net.add_node(node['id'], font=font, **options)
    for edge in model['edges']:
        options = {k: v for k, v in edge.items() if k not in ('from', 'to')}
        net.add_edge(
            edge['from'],
            edge['to'],
            font={'size': 11, 'color': '#cbd5e1', 'strokeWidth': 0, 'align': 'middle'},
            arrows='to',
            **options,
        )
    # Tree layout: le coordinate di graph_model sono definitive, non un punto di partenza per la
    # simulazione fisica.
    net.toggle_physics(False)
    return net


def build_correlation_graph(
    correlations: Dict[str, Any],
    redacted: bool = True,
    guard: Optional[PrivacyGuard] = None,
    filters: Optional[Iterable[str]] = None,
    checked_at: Optional[str] = None,
) -> 'Network':
    """Build the investigation graph from a report's correlations (no network calls).

    Raises:
        RuntimeError: If the optional ``graph`` extra (pyvis) is not installed.
    """
    _require_pyvis()
    model = graph_model(correlations, redacted=redacted, guard=guard, checked_at=checked_at)
    return network_from_model(filter_model(model, filters))


def render_graph_html(network: 'Network') -> str:
    """Self-contained HTML for the graph: no external resources, or RuntimeError.

    Raises:
        RuntimeError: If an external resource (attribute, srcset, CSS @import/url(), embedding
            tag, network API, protocol-relative URL...) is still referenced after cleaning: fails
            closed rather than writing a file that contacts a third party when opened.
    """
    html = _EXTERNAL_TAG.sub('', network.generate_html())
    # pyvis switches to a custom popup doing `popup.innerHTML = nodeData[0].title` as soon as any node
    # title contains 'href'; titles carry target-controlled text, so it must be shown as text.
    html = html.replace('popup.innerHTML = nodeData[0].title', 'popup.textContent = nodeData[0].title')
    if _INNER_HTML_FROM_DATA.search(html):
        raise RuntimeError('Graph HTML renders node data as HTML (pyvis template changed); refusing to write it.')
    html = html.replace('</body>', _LEGEND + _CARD_JS + '</body>', 1)
    found = external_references(html)
    if found:
        raise RuntimeError(
            f'Graph HTML still references external resources ({", ".join(found)}); refusing to write it.'
        )
    return html


def external_references(html: str) -> List[str]:
    """Names of the external-resource checks ``html`` trips; an empty list means self-contained.

    See the comment above ``_MARKUP_CHECKS`` for what is checked where, and why node data (JSON
    strings inside scripts) cannot trigger a false refusal.
    """
    scripts: List[str] = []

    def keep_tags(match: 're.Match[str]') -> str:
        scripts.append(match.group(2))
        return match.group(1) + match.group(3)

    markup = _SCRIPT_BLOCK.sub(keep_tags, html)
    found = [name for name, pattern in _MARKUP_CHECKS if pattern.search(markup)]
    if _NETWORK_API.search(markup):  # inline handlers such as onload="fetch(...)" live in the markup
        found.append('network API in markup')
    found.extend(name for name, pattern in _SCRIPT_URL_CHECKS if any(pattern.search(body) for body in scripts))
    if any(_NETWORK_API.search(_JS_DOUBLE_QUOTED.sub('""', body)) for body in scripts):
        found.append('network API in script')
    return found


def save_graph_html(network: 'Network', path: Path) -> Path:
    """Write the self-contained interactive HTML graph with owner-only (0600) permissions."""
    path = Path(path)
    _write_private(str(path), render_graph_html(network))
    return path


def graph_filename(case_id: Optional[str]) -> str:
    """``<case-id>_graph.html`` with the case ID reduced to safe characters, else ``latest_graph.html``.

    The case ID is user input: path separators and anything outside ``[A-Za-z0-9._-]`` become
    ``_``, and leading dots are stripped, so it can never escape the reports directory.
    """
    stem = _SAFE_STEM.sub('_', (case_id or '').strip()).strip('._')[:80]
    return f'{stem or "latest"}_graph.html'
