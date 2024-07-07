package org.acme.secuirty;

import io.quarkus.security.credential.CertificateCredential;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import java.util.function.Supplier;

@ApplicationScoped
public class RolesAugmentor implements SecurityIdentityAugmentor {

    @ConfigProperty(name = "disable.mtls", defaultValue = "true")
    boolean disableMtls;

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
        if(disableMtls){
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder(identity).build());
        }
        return Uni.createFrom().item(build(identity));
    }

    private Supplier<SecurityIdentity> build(SecurityIdentity identity) {
        // create a new builder and copy principal, attributes, credentials and roles from the original identity
        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder(identity);

        CertificateCredential certificate = identity.getCredential(CertificateCredential.class);
        if (certificate != null) {
            String name = certificate.getCertificate().getSubjectX500Principal().getName();
            System.out.println("Cert common name ,"+name);
            if("CN=krish-client".equals(name)){
                return builder::build;
            }else{
                throw new RuntimeException("Unknown requestor");
            }
        }else{
            throw new RuntimeException("Unknown requestor");
        }
    }

}