#!/bin/sh

echo "creating archive for installation"
cd /jffs/dnsmasq
rm adbhostgen.tar.gz
rm installer.sh
tar czf adbhostgen.tar.gz .

echo "Generating installer stub"
cat << 'EOF' >> installer.sh
#!/bin/sh

echo "============================================"
echo "|       Installing adblock for DD-WRT      |"
echo "| https://github.com/m-parashar/adbhostgen |"
echo "|      Copyright 2018 Manish Parashar      |"
echo "============================================"

# Create destination folder
DESTINATION="/jffs/dnsmasq"
mkdir -p ${DESTINATION}

# Find __ARCHIVE__ maker, read archive content and decompress it
ARCHIVE=$(awk '/^__ARCHIVE__/ {print NR + 1; exit 0; }' "${0}")
tail -n+${ARCHIVE} "${0}" | tar xzv -C ${DESTINATION}

# Any post-installation tasks

echo ""
echo "Installation complete."
echo "Don't forget to run adbhostgen.sh in ${DESTINATION}"
echo ""

# Exit from the script with success (0)
exit 0

__ARCHIVE__
EOF

echo "Creating installer for adbhostgen"
cat adbhostgen.tar.gz >> installer.sh
chmod +x installer.sh

echo "installer created."
