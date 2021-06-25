BINDIR=./bin
SRCDIR=./src
DOCDIR=./javadocs


default:
	javac ${SRCDIR}/CertificateAuthority.java --add-exports java.base/sun.security.x509=ALL-UNNAMED -Xlint:-deprecation -cp ${BINDIR} -d ${BINDIR}
	javac ${SRCDIR}/RSAKeyGenerator.java ${SRCDIR}/Cryptography.java ${SRCDIR}/Server.java ${SRCDIR}/Client.java -cp ${BINDIR} -d ${BINDIR}

clean:
	rm -f ${BINDIR}/*.class