<%@ taglib uri="http://rhn.redhat.com/rhn" prefix="rhn" %>
<%@ taglib uri="http://rhn.redhat.com/tags/list" prefix="rl" %>
<%@ taglib uri="http://rhn.redhat.com/tags/config-managment" prefix="cfg" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<head>
    <meta name="name" value="sdc.config.jsp.header" />
</head>
<body>
<%@ include file="/WEB-INF/pages/common/fragments/systems/system-header.jspf" %>

<h2><img class="h2-image" src="${cfg:channelHeaderIcon('local')}"
			alt="${cfg:channelAlt('local')}"/>
		<bean:message key="sdc.config.header.overview"/></h2>
		<p><bean:message key="sdc.config.file_list.local_description"/></p>

<rl:listset name="fileSet">

	<!-- Start of Files list -->
	<rl:list decorator="SelectableDecorator"
             width="100%"
			 filter="com.redhat.rhn.frontend.action.configuration.sdc.ViewModifyPathsFilter"
             emptykey = "channelfiles.jsp.noFiles"
	         >
	    <rl:selectablecolumn value="${current.selectionKey}"
						selected="${current.selected}"
	    					styleclass="first-column"/>

		<!-- File name column -->
		<rl:column bound = "false"
				   sortable="true"
		           headerkey="sdc.config.file_list.name"
		           sortattr="path"
		           >
		     <cfg:file path="${current.path}"
				type ="${current.localConfigFileType}" nolink = "true"/>
		</rl:column>
		
		<!-- Actions -->
		<rl:column bound="false"
		           headerkey="sdc.config.file_list.actions">
			<bean:message key="sdc.config.file_list.edit_or_compare"
         					arg0 ="${cfg:fileUrl(current.localConfigFileId)}"
         				    arg1="${cfg:fileCompareUrl(current.localConfigFileId)}"/>
		</rl:column>

       	<!-- Overrides-->
	<rl:column bound="false"
	           headerkey="sdc.config.file_list.overrides"
       				>
       		<c:choose>       		
   	       		<c:when test="${current.configRevision != null}">
					<c:set var="channelDisplay"><cfg:channel id = "${current.configChannelId}"
							name ="${current.configChannelName}"
							type = "central"/>
   					</c:set>
      	       		<bean:message key="sdc.config.file_list.revision_from"
    	       				arg0 = "${cfg:fileRevisionUrl(current.configFileId, current.configRevisionId)}"
    	       				arg1 = "${cfg:fileListIcon(current.configFileType)}"
    	       				arg2 = "${rhn:localize(cfg:fileAlt(current.configFileType))}"
       	       				arg3 = "${current.configRevision}"
       	       				arg4 = "${channelDisplay}"
       	       				/>
                </c:when>
                <c:otherwise>
       	       			<bean:message key="sdc.config.file_list.none"/>
                </c:otherwise>
           </c:choose>
       	</rl:column>
		<!-- Current Revision -->
		<rl:column bound="false"
		           headerkey="sdc.config.file_list.current_revision"
				   styleclass="last-column"
					>
		       		<c:set var = "revisionLook">
				       		<bean:message key="sdcconfigfiles.jsp.filerev"
				       					arg0="${current.localRevision}"/>		
		       		</c:set>
					<cfg:file path ="${revisionLook}"
							type ="${current.localConfigFileType}"
							id = "${current.localConfigFileId}"
							revisionId = "${current.localRevisionId}"
							/>		       		
		</rl:column>
	</rl:list>
	<br>
	<c:import url="/WEB-INF/pages/common/fragments/configuration/sdc/viewmodifyfileactions.jspf"/>
 </rl:listset>
</body>
</html>
