# Audit de Sécurité — Extension upStart

**Date :** 2026-03-20
**Version :** 2
**Type :** Extension Chrome (Manifest v2)

---

## Résumé des risques

| # | Titre | Sévérité | Fichier(s) |
|---|-------|----------|------------|
| 0 | **Credentials Dropbox hardcodés dans le code source** | **CRITIQUE** | `settings.js:2037-2038` |
| 1 | XSS via `innerHTML` sur données utilisateur | **Critique** | `functions.js`, `init.js`, `settings.js`, `popup.js` |
| 2 | Injection d'URL arbitraire (`javascript:` protocol) | **Critique** | `functions.js:940` |
| 3 | Implémentation OAuth2 non sécurisée | **Critique** | `settings.js:2039-2080` |
| 4 | Token Dropbox stocké en `localStorage` | **Haute** | `functions.js`, `background.js` |
| 5 | Permissions excessives dans le manifeste | **Haute** | `manifest.json` |
| 6 | Import de fichiers sans validation | **Haute** | `settings.js:1028-1193` |
| 7 | Récupération de favicons depuis des sources non fiables (SSRF) | **Haute** | `functions.js:1586-1750` |
| 8 | `web_accessible_resources` trop large | **Moyenne** | `manifest.json` |
| 9 | Manifest Version 2 obsolète | **Moyenne** | `manifest.json` |
| 10 | Permission `management` trop puissante | **Moyenne** | `manifest.json` |
| 11 | Absence de validation stricte des URLs | **Moyenne** | `functions.js` |
| 12 | Journalisation de données sensibles | **Faible** | `background.js`, `functions.js` |
| 13 | Boucle `for...in` sans `hasOwnProperty` | **Faible** | `background.js:44` |

---

## Détail des vulnérabilités

### 0. Credentials Dropbox hardcodés dans le code source (CRITIQUE — À corriger immédiatement)

L'App Key et l'App Secret Dropbox sont écrits en clair dans le code JavaScript côté client.

```js
// settings.js:2037-2038
let dbxAppKey = 'pb82c8abics6xcp'
let dbxAppSecret = 'zp6z78ekv7pu6zd'

// settings.js:2047 — envoyés dans chaque requête OAuth2
headers.append('Authorization', 'Basic ' + btoa(dbxAppKey + ":" + dbxAppSecret))
```

**Impact :**
- N'importe qui ayant accès à l'extension (téléchargée depuis le Web Store, ou au code source) peut extraire ces credentials.
- Un attaquant peut usurper l'identité de l'application dans le flux OAuth2 Dropbox.
- Permet d'échanger des codes d'autorisation contre des tokens d'accès utilisateur.
- Ces credentials sont compromis dès lors qu'ils apparaissent dans un dépôt public.

**Correction recommandée :**
- **Révoquer immédiatement** ces credentials sur le portail développeur Dropbox.
- Ne jamais stocker de secrets dans du code client.
- Implémenter un backend proxy sécurisé pour l'échange de tokens OAuth2.
- Utiliser le flux PKCE (Proof Key for Code Exchange) qui ne nécessite pas de secret côté client.

---

### 1. XSS via `innerHTML` sur données utilisateur (Critique)

Des données contrôlées par l'utilisateur sont injectées directement dans le DOM via `innerHTML` sans aucune sanitisation. Si un attaquant peut modifier les données stockées (import malveillant, corruption de `chrome.storage`), il peut exécuter du JavaScript arbitraire dans le contexte de l'extension.

**Occurrences principales :**

```js
// functions.js:975 — label du signet
bookmarkLabel.innerHTML = item.label

// functions.js:814 — label du groupe
groupLabel.innerHTML = group.groupLabel

// functions.js:853 — description du groupe
groupDescription.innerHTML = group.groupDescription

// functions.js:672 — label de page
topNavPage.innerHTML = jsonData.pages[pageID].pageLabel

// init.js:134 — injection complète du DOM depuis le storage
document.body.innerHTML = domData.upStartDOM

// settings.js:400 — preview de sauvegarde
bkpPreviewContent.innerHTML += await drawDOM(bkpData.data)
```

**Correction recommandée :** Utiliser `textContent` pour les chaînes textuelles, ou `DOMPurify` pour le contenu qui nécessite du HTML.

```js
// Au lieu de :
bookmarkLabel.innerHTML = item.label
// Utiliser :
bookmarkLabel.textContent = item.label
```

---

### 2. Injection d'URL arbitraire — `javascript:` protocol (Critique)

L'URL des signets est assignée directement à `href` sans validation du protocole. Un signet malveillant avec `javascript:alert(document.cookie)` s'exécuterait au clic.

```js
// functions.js:940
if (item.url) { bookmarkLink.href = item.url }
```

**Correction recommandée :** Valider que le protocole est `http:`, `https:` ou `file:` avant d'assigner.

```js
function isSafeUrl(url) {
  try {
    const parsed = new URL(url)
    return ['http:', 'https:', 'file:'].includes(parsed.protocol)
  } catch { return false }
}
if (item.url && isSafeUrl(item.url)) { bookmarkLink.href = item.url }
```

---

### 3. Token Dropbox stocké en `localStorage` (Haute)

Le token d'accès Dropbox est stocké en clair dans `localStorage` sous la clé `upStart_dbxToken`. Si une faille XSS est exploitée (voir #1), ce token peut être exfiltré, donnant un accès complet au compte Dropbox de l'utilisateur.

```js
// background.js:9, functions.js:2001, 2031, 2080
let ACCESS_TOKEN = localStorage.getItem("upStart_dbxToken")
```

**Correction recommandée :** Utiliser `chrome.storage.local` (chiffré, non accessible via XSS) au lieu de `localStorage`.

---

### 4. Permissions excessives dans le manifeste (Haute)

```json
"permissions": [ "file:///*/", "tabs", "management", "alarms", "storage",
  "unlimitedStorage", "contextMenus", "<all_urls>", "notifications", "bookmarks" ]
```

- **`<all_urls>`** : accès à toutes les pages web — inutile pour un gestionnaire de signets.
- **`file:///*/`** : accès aux fichiers locaux — vecteur d'attaque sensible.
- **`management`** : permet de lire/modifier/désactiver toutes les extensions installées.

**Correction recommandée :** Restreindre aux permissions strictement nécessaires. Supprimer `management` si non utilisé, remplacer `<all_urls>` par des hôtes spécifiques.

---

### 5. `web_accessible_resources` trop large (Moyenne)

```json
"web_accessible_resources": ["js/*.json", "newtab.html"]
```

Tous les fichiers `.json` du dossier `js/` (y compris `upStartData_en.json`, `upStartSettings.json`) sont accessibles par n'importe quel site web via `chrome-extension://`. Cela expose les données par défaut et la structure interne.

**Correction recommandée :** Lister uniquement les ressources effectivement nécessaires aux pages web externes.

---

### 6. Manifest Version 2 obsolète (Moyenne)

L'extension utilise `"manifest_version": 2`, déprécié depuis Chrome 112 et désactivé dans Chrome 127+. MV2 présente des risques de sécurité supprimés dans MV3 (notamment l'accès réseau non restreint depuis le service worker).

**Correction recommandée :** Migrer vers Manifest V3.

---

### 7. Permission `management` trop puissante (Moyenne)

La permission `management` permet à l'extension de lister, activer, désactiver ou désinstaller d'autres extensions. Si l'extension est compromise, un attaquant pourrait désactiver des extensions de sécurité (bloqueurs de publicité, gestionnaires de mots de passe, etc.).

**Correction recommandée :** Vérifier si cette permission est réellement utilisée dans le code. Si non, la supprimer du manifeste.

---

### 8. Absence de validation à l'import (Moyenne)

Lors de l'import de signets (depuis Chrome, Firefox, ou un fichier JSON), les données importées sont utilisées directement sans validation ni sanitisation :

```js
// functions.js — import de données externes
let jsonImportedData = JSON.parse('{ "pages": [], "groups": [], "items": [] }')
// ... données ajoutées sans validation des valeurs
```

**Correction recommandée :** Valider et sanitiser toutes les valeurs importées (labels, URLs, descriptions) avant de les stocker.

---

### 9. Journalisation de données sensibles (Faible)

Plusieurs `console.log` exposent des informations sensibles dans la console du navigateur :

```js
// background.js
console.log("browser start")
console.log("remoteServerModified", remoteServerModified)
console.log("Dropbox data synchronized")
// functions.js - état de synchronisation
```

Ces logs peuvent aider un attaquant à comprendre l'état de l'extension. En production, les logs verbeux devraient être supprimés.

---

### 10. Boucle `for...in` sans `hasOwnProperty` (Faible)

```js
// background.js:44
for (key in changes) {
  if (key == 'upStartData') { ... }
}
```

Sans vérification `hasOwnProperty`, des propriétés héritées du prototype peuvent être itérées, menant à un comportement inattendu (risque de prototype pollution).

**Correction recommandée :**
```js
for (const key of Object.keys(changes)) { ... }
```

---

## Composants tiers utilisés

| Composant | Usage | Risque |
|-----------|-------|--------|
| `dropbox.min.js` | Synchronisation cloud | Dépendance externe, vérifier la version |
| `lz-string.min.js` | Compression des données | Faible |
| `sweetalert2.min.js` | Dialogues modaux | Faible |
| `sortable.min.js` | Drag & drop | Faible |
| `jszip.min.js` | Export/import ZIP | Faible |
| `pickr.min.js` | Sélecteur de couleur | Faible |
| `iziToast.min.js` | Notifications | Faible |
| `FileSaver.min.js` | Téléchargement de fichiers | Faible |
| `fontawesome-custom.min.js` | Icônes | Faible |
| `chrome-extension-async.js` | Wrappers async Chrome API | Faible |

**Note :** Les fichiers minifiés bundlés localement (`dropbox.min.js`, etc.) ne bénéficient pas des mises à jour automatiques de sécurité. Il est recommandé de vérifier les versions et de les mettre à jour régulièrement.

---

## Priorités de correction

1. **[Immédiat]** Révoquer les credentials Dropbox exposés (`pb82c8abics6xcp` / `zp6z78ekv7pu6zd`) et en générer de nouveaux (#0)
2. **[Immédiat]** Implémenter un backend proxy pour l'échange OAuth2 ou utiliser PKCE (#0, #3)
3. **[Immédiat]** Remplacer `innerHTML` par `textContent` pour toutes les données utilisateur (#1)
4. **[Immédiat]** Valider le protocole des URLs avant assignation à `href` (#2)
5. **[Court terme]** Migrer le token Dropbox vers `chrome.storage.local` (#4)
6. **[Court terme]** Ajouter une validation stricte des données importées (#6)
7. **[Court terme]** Réduire les permissions du manifeste — supprimer `<all_urls>`, `management`, `file:///*/` (#5)
8. **[Moyen terme]** Migrer vers Manifest V3 (#9)
9. **[Moyen terme]** Ajouter une validation d'URL stricte (whitelist de protocoles) (#11)
