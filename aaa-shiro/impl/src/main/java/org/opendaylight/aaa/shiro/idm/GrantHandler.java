package org.opendaylight.aaa.shiro.idm;
import org.opendaylight.aaa.api.IDMStoreException;
import org.opendaylight.aaa.api.IIDMStore;
import org.opendaylight.aaa.api.model.Grants;
import org.opendaylight.aaa.api.model.IDMError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.util.Objects;

@Path("/v1/grants")
public class GrantHandler {
    private static final Logger LOG = LoggerFactory.getLogger(DomainHandler.class);

    private final IIDMStore iidMStore;
    //private final ClaimCache claimCache;

    public GrantHandler(IIDMStore iidMStore) {
        this.iidMStore = Objects.requireNonNull(iidMStore);
        //this.claimCache = Objects.requireNonNull(claimCache);
    }

    @GET
    @Path("/{id}")
    @Produces("application/json")
    public Response getGrants(@PathParam("id") String id) {
        LOG.info("Get /grants");
        Grants grants = null;
        try {
            grants = iidMStore.getGrants(id);
        } catch (IDMStoreException e) {
            LOG.error("StoreException", e);
            IDMError idmerror = new IDMError();
            idmerror.setMessage("Internal error getting grants");
            idmerror.setDetails(e.getMessage());
            return Response.status(500).entity(idmerror).build();
        }
        return Response.ok(grants).build();
    }

}
