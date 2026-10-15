# Notices tierces — WIFX Voice Probe Agent

Les sources originales WIFX de l’Agent sont GPL-3.0-or-later. Les tiers restent sous leurs licences respectives ; aucune licence WIFX ne leur est attribuée.

| Composant | Licence / obligations |
|---|---|
| PJSIP/PJSUA2 2.16 | GPL-2.0-or-later, exceptions PJSIP ; sources exactes et recette de construction fournies |
| G.722, PCMA/PCMU inclus dans PJSIP | domaine public / notices amont conservées |
| resample, GNU getopt | LGPL, sources PJSIP et notices conservées |
| GSM, Speex, iLBC, SRTP, WebRTC | licences permissives originales, attribution conservée ; voir notices PJSIP |
| NumPy 1.26.4 | BSD et notices des composants ; wheel WIFX modifié pour bibliothèques système Fortran/quadmath |
| OpenBLAS c2f4bdbb / LAPACK | BSD, notices exactes conservées ; code source fourni |
| Requests 2.33.0 | Apache-2.0 et NOTICE |
| urllib3 2.8.0, charset-normalizer 3.5.2 | MIT |
| idna 3.20, websockets 15.0.1 | BSD-3-Clause |
| certifi 2026.7.22 | MPL-2.0 ; sources et bundle certificats fournis |
| Python et bibliothèques Debian de l’image | licences dans /usr/share/doc ; inventaire des versions et sources Debian exactes fournis |
| OpenSSL 3 | Apache-2.0, dynamique ; notices et sources Debian dans la distribution Docker |
| GNU libc, libgfortran, libquadmath, runtimes GCC | licences/exception GCC propres ; bibliothèques système remplaçables, sources exactes fournies pour l’image Debian |

Les bibliothèques libgfortran/libquadmath initialement vendues dans les wheels NumPy amont ne sont pas redistribuées dans les SDK publics. Leur substitution est tracée dans WIFX-PROVENANCE.json ; elles sont installées par le gestionnaire de paquets du système. Les fichiers de licence NumPy originaux sont conservés, même lorsqu’ils décrivent ces bibliothèques désormais absentes du wheel WIFX.

Les sources correspondantes sont livrées comme asset de la même Release, avec SHA-256 dans le manifeste signé. L’archive conserve les sources PJSIP 2.16, les sources Python exactes, OpenBLAS et les sources des 86 paquets Debian de l’image de référence ; l’inventaire final de l’image doit être comparé avant publication. Les compilateurs et SWIG ne sont pas installés sur les clients.

PJSIP : https://docs.pjsip.org/en/2.16/overview/license_pjsip.html ; tiers : https://docs.pjsip.org/en/2.16/overview/license_3rd_party.html
