# WIFX Voice Probe Agent

Copyright 2026 WIFX. Les sources originales de cet Agent et de l’outillage Agent publié sont sous GPL-3.0-or-later, sur décision de WIFX. Cette déclaration ne concerne ni le Controller privé ni les composants tiers.

PJSIP/PJSUA2 2.16 reste sous GPL-2.0-or-later avec ses exceptions. Les autres composants conservent leurs licences, notices et auteurs. Les distributions publiques fournissent les notices et les sources correspondantes dans les assets de la Release.

Sur Linux, NumPy 1.26.4 conserve ses algorithmes et son BLAS. Le wheel WIFX retire les bibliothèques Fortran/quadmath embarquées et utilise les bibliothèques système déclarées. Le fichier WIFX-PROVENANCE.json du wheel décrit précisément cette transformation. Aucune compilation n’est effectuée sur les cibles normales.

Le candidat Windows portable utilise CPython 3.13.16 et NumPy 2.5.4, avec les runtimes de ses wheels Windows exactes. Il reste une distribution LAB non signée Authenticode ; les notices et sources collectées pour Windows sont distinctes des archives Linux. Aucun binaire Windows client n’est publié à ce stade.
