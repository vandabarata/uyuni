/**
 * Copyright (c) 2011 Novell
 *
 * This software is licensed to you under the GNU General Public License,
 * version 2 (GPLv2). There is NO WARRANTY for this software, express or
 * implied, including the implied warranties of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
 * along with this software; if not, see
 * http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * Red Hat trademarks are not licensed under GPLv2. No permission is
 * granted to use or replicate Red Hat trademarks that are incorporated
 * in this software or its documentation.
 */
package com.redhat.rhn.frontend.action.systems.images;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;
import org.apache.struts.action.DynaActionForm;

import com.redhat.rhn.domain.action.Action;
import com.redhat.rhn.domain.image.Image;
import com.redhat.rhn.domain.image.ImageFactory;
import com.redhat.rhn.domain.org.Org;
import com.redhat.rhn.domain.server.Server;
import com.redhat.rhn.domain.user.User;
import com.redhat.rhn.frontend.struts.RequestContext;
import com.redhat.rhn.frontend.struts.RhnListAction;
import com.redhat.rhn.frontend.taglibs.list.ListTagHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.ListHelper;
import com.redhat.rhn.frontend.taglibs.list.helper.Listable;
import com.redhat.rhn.manager.action.ActionManager;
import com.redhat.rhn.manager.system.SystemManager;
import com.suse.studio.client.SUSEStudioClient;
import com.suse.studio.client.data.Appliance;
import com.suse.studio.client.data.Build;

/**
 * This action will present the user with a list of available images
 * and allow one to be selected for provisioning.
 */
public class ScheduleImageDeploymentAction extends RhnListAction implements Listable {

    private static final String DATA_SET = "pageList";
    private static final String SUCCESS_KEY = "studio.deployment.scheduled";

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    public ActionForward execute(ActionMapping actionMapping,
                                 ActionForm actionForm,
                                 HttpServletRequest request,
                                 HttpServletResponse response)
        throws Exception {

    	Boolean submitted = false;
        Long sid = null;
    	Long vcpus = null;
    	Long memkb = null;
    	String bridge = null;

    	// Read parameters from the form
        if (actionForm instanceof DynaActionForm) {
            DynaActionForm form = (DynaActionForm) actionForm;
            sid = (Long) form.get("sid");

            // Read submitted
            submitted = (Boolean) form.get("submitted");
            submitted = submitted ==  null ? false : submitted;

            if (submitted) {
                // Get the form parameters
                vcpus = (Long) form.get("vcpus");
                memkb = (Long) form.get("mem_mb") * 1024;
                bridge = (String) form.getString("bridge");
            }
        }

        // Get the current user
        RequestContext ctx = new RequestContext(request);
        User user = ctx.getLoggedInUser();

        ActionForward forward;
        if (submitted) {
            // Schedule image deployment
            String buildId = ListTagHelper.getRadioSelection(ListHelper.LIST, request);

            // Get the images from the session and find the selected one
            List<Image> images = (List<Image>) request.getSession().getAttribute("images");
            request.getSession().removeAttribute("images");
            Image image = null;
            for (Image i : images) {
                if (i.getBuildId().equals(new Long(buildId))) {
                    image = i;
                    break;
                }
            }

        	// Create the action and store it
            Action deploy = ActionManager.createDeployImageAction(
                    user, image, vcpus, memkb, bridge);
            ActionManager.addServerToAction(sid, deploy);
            ActionManager.storeAction(deploy);
            // Put a success message to the request
            createSuccessMessage(request, SUCCESS_KEY, image.getName());

            // Forward the sid as a request parameter
            Map forwardParams = makeParamMap(request);
            forwardParams.put("sid", sid);
            forward = getStrutsDelegate().forwardParams(
                    actionMapping.findForward("success"), forwardParams);
        } else {
            // Put the server to the request for the header
            Server server = SystemManager.lookupByIdAndUser(sid, user);
            request.setAttribute("system", server);

            // Setup the list of images
            ListHelper helper = new ListHelper(this, request);
            helper.setDataSetName(DATA_SET);
            helper.execute();

            // Temporarily write images to the session
            request.getSession().setAttribute("images", helper.getDataSet());

            forward = actionMapping.findForward("default");
        }
        return forward;
    }

    /** {@inheritDoc} */
    public List getResult(RequestContext context) {
        List<Appliance> ret = new ArrayList<Appliance>();

        // Take credentials stored with the org
        Org org = context.getCurrentUser().getOrg();
        String user = org.getStudioUser();
        String apikey = org.getStudioKey();

        // Get appliance builds from studio
        if (user != null && apikey != null) {
            SUSEStudioClient client = new SUSEStudioClient(user, apikey);
            try {
                ret = client.getAppliances();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        // Convert to a list of images
        return createImageList(ret, context);
    }

    /**
     * Create an {@link Image} object out of every build of an appliance.
     * @param appliances
     * @return list of images
     */
    private List<Image> createImageList(List<Appliance> appliances,
            RequestContext context) {
        List<Image> ret = new LinkedList<Image>();
        for (Appliance appliance : appliances) {
            // Create one image object for every build
            for (Build build : appliance.getBuilds()) {
                Image img = ImageFactory.createImage();
                img.setOrg(context.getCurrentUser().getOrg());
                // Appliance attributes
                img.setName(appliance.getName());
                img.setArch(appliance.getArch());
                // Build attributes
                img.setBuildId(new Long(build.getId()));
                img.setVersion(build.getVersion());
                img.setImageType(build.getImageType());
                img.setDownloadUrl(build.getDownloadURL());
                ret.add(img);
            }
        }
        return ret;
    }
}
