# Licences et sources correspondantes

Sources originales WIFX Agent/outillage : GPL-3.0-or-later. Le Controller privé est exclu. PJSIP2.16 : GPL-2.0-or-later avec ses exceptions. Les notices originales sont conservées sans réattribution de licence.

La Release fournit les sources PJSIP, Python/NumPy/OpenBLAS et les sources Debian correspondant aux bibliothèques de l’image, avec inventaire et empreintes. Les sources Agent sont celles du tag/commit public indiqué dans le manifeste signé. Les recettes de compilation et de transformation sont dans scripts/.

Le wheel NumPy WIFX conserve ses algorithmes ; il retire ses deux runtimes Fortran/quadmath vendus et les remplace par les bibliothèques système déclarées. WIFX-PROVENANCE.json trace l’original et les modifications. Le client ne compile rien.
