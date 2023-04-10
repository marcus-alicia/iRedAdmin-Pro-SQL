#!/usr/bin/env bash

# Author:    Zhang Huangbin (zhb _at_ iredmail.org)

#---------------------------------------------------------------------
# This file is part of iRedAdmin-Pro, which is official web-based admin
# panel (Full-Featured Edition) for iRedMail.
#
# ---- Restrictions ----
# * Source code is only available after you purchase it, so that you can
#   modify it to fit your need, but it is NOT allowed to redistribute
#   and sell iRedAdmin and the one you modified based on iRedAdmin.
#
# * We will do our best to solve all bugs found in official iRedAdmin,
#   but we are not guarantee to solve bugs occured in your modified copy.
#
# * It is NOT allowed to deployed on more than 1 server.
#
#---------------------------------------------------------------------

# Available actions: [all, LANG].
ACTIONORLANG="$1"

if [ -z "${ACTIONORLANG}" ]; then
    cat <<EOF

Usage: $0 [all, LANGUAGE]

Example:

    $ $0 all
    $ $0 zh_CN
    $ $0 fr_Fr

EOF
    exit 255
fi

DOMAIN="iredadmin"
POFILE="${DOMAIN}.po"
#AVAILABLE_LANGS="$(ls -d *_*)"
AVAILABLE_LANGS="$(ls -ld * | awk '/^d/ {print $NF}')"

extract_latest()
{
    # Extract strings from template files.
    echo "* Extract localizable messages from template files to ${POFILE}..."

    pybabel extract \
        -F babel.cfg \
        --no-location \
        --omit-header \
        --sort-output \
        --charset=utf-8 \
        --msgid-bugs-address=support@iredmail.org \
        -o ${POFILE} \
        .. >/dev/null
}

update_po()
{
    # Update PO files.
    echo "* Updating existing translations ..."

    for lang in ${LANGUAGES}
    do
        pofile="${lang}/LC_MESSAGES/${DOMAIN}.po"

        [ -d ${lang}/LC_MESSAGES/ ] || mkdir -p ${lang}/LC_MESSAGES/
        pybabel update --ignore-obsolete\
            -i ${POFILE} \
            -D ${DOMAIN} \
            -d . \
            -l ${lang}

        # Remove 'fuzzy' tag.
        perl -pi -e 's/#, fuzzy//' ${pofile}

        # Comment ', python-format'.
        perl -pi -e 's/^(, python-format.*)/#${1}/' ${pofile}

        # Update 'Project-Id-Version'
        perl -pi -e 's#^("Project-Id-Version:).*#${1} iRedAdmin-Pro\\n"#g' ${pofile}
        perl -pi -e 's#^("POT-Creation-Date:.*\n)##g' ${pofile}
        perl -pi -e 's#^("Report-Msgid-Bugs-To:.*\n)##g' ${pofile}
    done
}

convert_po_to_mo()
{
    for lang in ${LANGUAGES}; do
        echo "  + Converting ${lang} ..."
        msgfmt --statistics --check-format ${lang}/LC_MESSAGES/${DOMAIN}.po -o ${lang}/LC_MESSAGES/${DOMAIN}.mo
    done
}

if [ X"${ACTIONORLANG}" == X"all" -o X"${ACTIONORLANG}" == X"" ]; then
    export LANGUAGES="${AVAILABLE_LANGS}"
else
    export LANGUAGES="$(basename ${ACTIONORLANG})"
fi

extract_latest && \
update_po && \
convert_po_to_mo
