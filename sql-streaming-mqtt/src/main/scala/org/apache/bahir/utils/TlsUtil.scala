package org.apache.bahir.utils

import java.io.FileReader
import java.security.cert.X509Certificate
import java.security.{KeyPair, KeyStore, Security}
import javax.net.ssl.{KeyManagerFactory, SSLContext, SSLSocketFactory, TrustManagerFactory}

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.{JcaPEMKeyConverter, JcePEMDecryptorProviderBuilder}
import org.bouncycastle.openssl.{PEMDecryptorProvider, PEMEncryptedKeyPair, PEMKeyPair, PEMParser}

object TlsUtil {

  def getSocketFactory(caCrtFile: String,
                       crtFile: String,
                       keyFile: String,
                       password: String): SSLSocketFactory = {

    /**
      * Add BouncyCastle as a Security Provider
      */
    Security.addProvider(new BouncyCastleProvider())
    val certificateConverter: JcaX509CertificateConverter =
      new JcaX509CertificateConverter().setProvider("BC")

    /**
      * Load Certificate Authority (CA) certificate
      */
    var reader: PEMParser = new PEMParser(new FileReader(caCrtFile))
    val caCertHolder: X509CertificateHolder =
      reader.readObject().asInstanceOf[X509CertificateHolder]
    reader.close()
    val caCert: X509Certificate =
      certificateConverter.getCertificate(caCertHolder)

    /**
      * Load client certificate
      */
    reader = new PEMParser(new FileReader(crtFile))
    val certHolder: X509CertificateHolder =
      reader.readObject().asInstanceOf[X509CertificateHolder]
    reader.close()
    val cert: X509Certificate =
      certificateConverter.getCertificate(certHolder)

    /**
      * Load client private key
      */
    reader = new PEMParser(new FileReader(keyFile))
    val keyObject: AnyRef = reader.readObject()
    reader.close()
    val provider: PEMDecryptorProvider =
      new JcePEMDecryptorProviderBuilder().build(password.toCharArray())
    val keyConverter: JcaPEMKeyConverter =
      new JcaPEMKeyConverter().setProvider("BC")
    var key: KeyPair = null
    key =
      if (keyObject.isInstanceOf[PEMEncryptedKeyPair]) {
        keyConverter.getKeyPair(
          keyObject
            .asInstanceOf[PEMEncryptedKeyPair]
            .decryptKeyPair(provider))
      }
      else keyConverter.getKeyPair(keyObject.asInstanceOf[PEMKeyPair])

    /**
      * CA certificate is used to authenticate server
      */
    val caKeyStore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType)
    caKeyStore.load(null, null)
    caKeyStore.setCertificateEntry("ca-certificate", caCert)
    val trustManagerFactory: TrustManagerFactory =
      TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm)
    trustManagerFactory.init(caKeyStore)

    /**
      * Client key and certificates are sent to server so it can authenticate the client
      */
    val clientKeyStore: KeyStore =
      KeyStore.getInstance(KeyStore.getDefaultType)
    clientKeyStore.load(null, null)
    clientKeyStore.setCertificateEntry("certificate", cert)
    clientKeyStore.setKeyEntry("private-key",
      key.getPrivate,
      password.toCharArray(),
      Array(cert))
    val keyManagerFactory: KeyManagerFactory =
      KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    keyManagerFactory.init(clientKeyStore, password.toCharArray())

    /**
      * Create SSL socket factory
      */
    val context: SSLContext = SSLContext.getInstance("TLSv1.2")
    context.init(keyManagerFactory.getKeyManagers,
      trustManagerFactory.getTrustManagers,
      null)

    /**
      * Return the newly created socket factory object
      */
    context.getSocketFactory
  }
}