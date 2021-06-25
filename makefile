BINDIR=./bin
SRCDIR=./src
DOCDIR=./javadocs


default:
	javac ${SRCDIR}/RSAKeyGenerator.java ${SRCDIR}/CertificateAuthority.java --add-exports java.base/sun.security.x509=ALL-UNNAMED -cp ${OUTDIR} -d ${OUTDIR}
	javac ${SRCDIR}/Cryptography.java ${SRCDIR}/Participant.java ${SRCDIR}/Server.java ${SRCDIR}/Client.java -cp ${OUTDIR} -d ${OUTDIR}

clean:
	rm -f ${BINDIR}/*.class
