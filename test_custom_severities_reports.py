'''
Created on Jan 7, 2014

Automation tests related with PLT-2963 Custom severities reporting updates
'''
import glob
from veracode.core.testbase import AutomationTestCase
from veracode.core.decorators import DwrSessionProvider, BrowserTest

from dwrlib import policymgr, application, analysis, sandbox, dynamic, \
    dynamicmp

from collections import namedtuple
from veracode import scans
import files
from veracode.web import pages, services
from dwrlib.vast import fetch as vast_fetch

import pyPdf
import time, os, re, pytest
from selenium.common.exceptions import NoSuchElementException
from dwrlib.codes import IssueSeverity, ScanStatus, \
    BusinessCriticality
from dwrlib.http import dwrmethods

AppInfo = namedtuple('AppInfo', 
                     'app static_scan_info dynamic_scan_info manual_scan_info')

StaticScanInfo = namedtuple("StaticScanInfo",
        "app_ver_id analysis_id analysis_unit_id sandbox_id")

DynamicScanInfo = namedtuple("DynamicScanInfo",
        "app_ver_id analysis_id analysis_unit_id sandbox_id")

DynamicMPInfo = namedtuple("DynamicMPInfo",
        "app_id app_ver_id analysis_unit_id dynamicmp_job_id")


@pytest.mark.every
@pytest.mark.nightly
class CustomSeverityReportsTest(AutomationTestCase):

    def setUp(self):
        AutomationTestCase.setUp(self) 
        # base sev is 3 (med) - should be 6 in javascans
        self.static_custom_sev = {"CWEId": 489, "severity": 5}
        # base sev is 3 (med)
        self.dynamic_custom_sev = {"CWEId": 296, "severity": 5}
        
        self.app_name = 'CustomSeverityReportsTestApp'

    @DwrSessionProvider('external', 'extseclead', 'internal')
    @BrowserTest
    def test_html_reports(self):
        """
        Testcase 01 - Test HTML Reports
        """
        jsid = self.external_session
        ext_accountid = jsid.loginAccount.accountId
        int_jsid = self.internal_session
        policy = self.configure_policy(jsid, None,
                    custom_sevs=[self.static_custom_sev, self.dynamic_custom_sev])
        app_info = self.configure_app(jsid, None, policy=policy,
                                      static=True, dynamicDs=True, manual=True)
        self.publish_app_scans(self.internal_session, app_info)
        custom_sevs = policymgr.get_policy_custom_severities(jsid, policy.policyId)
        cwes = dwrmethods.getUserVisibleCWEs(jsid)
        self.verify_html_report(jsid, ext_accountid, app_info,
                                custom_sevs, cwes)


    @BrowserTest
    @DwrSessionProvider("external","internal")
    def test_pdf_reports(self):
        """
        Test Case 2: PDF Reports
        """
        jsid = self.external_session
        ext_accountid = jsid.loginAccount.accountId
        int_jsid = self.internal_session
        policy = self.configure_policy(jsid, None,
                custom_sevs=[self.static_custom_sev, self.dynamic_custom_sev])
        app_info = self.configure_app(jsid, None,
                    policy=policy, static=True, dynamicDs=True, manual=True)
        time.sleep(5)
        custom_sevs = policymgr.get_policy_custom_severities(jsid, policy.policyId)
        cwes = dwrmethods.getUserVisibleCWEs(jsid)
        self.verify_report(jsid, ext_accountid, app_info, policy, custom_sevs, cwes)

    @BrowserTest
    @DwrSessionProvider("external","vendor")
    def test_vast_shared_reports(self):
        """
        Test Case 3:VAST Shared reports.
        """
        app_name = "%s_app" % (self.current_name())
        policy_name = "%s_policy" % (self.current_name())
        report_name = "%s_report" % (self.current_name())
        jsid = self.external_session
        ext_accountid = jsid.loginAccount.accountId

        vast_policy = policymgr.fetch_vast_policy(self.external_session,
        policy_name, custom_sevs=[self.static_custom_sev])
        vendor_app = application.fetch_app(self.vendor_session, app_name)
        si_dynamic, si_manual = None, None
        si_static = scans.fetch_static_scan(
        self.vendor_session, vendor_app, modules=[files.JAVASCANS]
        )
        # generate and share the report
        vast_fetch.fetch_vast_report(
            self.vendor_session,
            self.external_session.loginAccount.accountId,
            vast_policy.policyId,
            vendor_app.appId,
            si_static.app_ver_id,
            report_name
        )

        vast_fetch.fetch_vast_app(
            self.external_session,
            self.vendor_session,
            vendor_app.appName,
            si_static.app_ver_id,
            auto_create=True,
            policy_name=policy_name,
            report_name=report_name
        )

        custom_sevs = policymgr.get_policy_custom_severities(jsid, vast_policy.policyId)
        cwes = dwrmethods.getUserVisibleCWEs(jsid)
        app_info = AppInfo(vendor_app, si_static, si_dynamic, si_manual)
        self.verify_report(jsid, self.vendor_session.loginAccount.accountId, app_info, vast_policy,
                           custom_sevs, cwes)

    @BrowserTest
    @DwrSessionProvider("external","vendor","internal")
    def test_cots_workflow(self):
        """
        Test case 4: COTS work flow.
        """
        ent_jsid = self.external_session
        int_jsid = self.internal_session
        ven_jsid = self.vendor_session
        cots_app_name = self.append_timestamp('CustSevRptCots')
        target_url = "http://rome.veracode.local"
        enterprise_acc_id = ent_jsid.loginAccount.accountId
        accountId = ven_jsid.loginAccount.accountId
        si_manual = None
        policy = self.configure_policy(ent_jsid, self.app_name,
                custom_sevs=[self.static_custom_sev, self.dynamic_custom_sev])
        app = None # we want to create a new one every time
        if app is None:
            app = application.createApp(ent_jsid, cots_app_name,accountId=accountId,
                                        enterpriseAccountId=enterprise_acc_id,
                                        policyGroupId=policy.policyGroupId)

        si = None # create a new one every time
        if si is None:
            staticAppVerId, staticAnalysisId, staticAnalysisUnitId = \
                sandbox.requestStaticCotsScan(ent_jsid, app.appId, accountId)
            application.acceptCotsAnalysis(ven_jsid, staticAnalysisUnitId)
            analysis.preflightFiles(ven_jsid, app.appId,
                                                   staticAppVerId, staticAnalysisUnitId,
                                                   files=[files.JAVASCANS])
            analysis.startStatic(ven_jsid, staticAppVerId,
                                 staticAnalysisUnitId,
                                 True)
            analysis.waitForPublish(int_jsid, staticAnalysisUnitId)

        si_dynamic = None # create a new one every time
        if si_dynamic is None:
            dynamicAppVerId, dynamicAnalysisId, dynamicAnalysisUnitId = \
                sandbox.requestDynamicCotsScan(ent_jsid, app.appId, accountId)
            application.acceptCotsAnalysis(ven_jsid, dynamicAnalysisUnitId)

            dynamic.configureScan(ven_jsid, dynamicAnalysisId, target_url, maxLinks=20)
            # dynamic.configureIncludeExcludeURLs(ven_jsid,
            #     cots_analysisUnitId, [target_url], [1], [False,], [], [], [])
            # dynamic.scheduleScan(ven_jsid, dynamicAnalysisUnitId,
            #                      runImmediately=True)
            dwrmethods.markDynamicAnalysisInProgress(int_jsid, dynamicAnalysisUnitId)
            dynamic.uploadResults(int_jsid, app.appId, dynamicAppVerId, dynamicAnalysisUnitId, files.DYNAMIC_RESULTS)
            # dynamic.runPrescan(ven_jsid, dynamicAnalysisUnitId, timeout=5)
            # analysis.startDynamic(ven_jsid, dynamicAppVerId,dynamicAnalysisUnitId, True)
            time.sleep(60)

            if not analysis.isPublished(int_jsid, dynamicAnalysisUnitId):
                analysis.publishAnalysis(int_jsid, dynamicAnalysisUnitId)

        time.sleep(3)
        application.publishMultipleAnalysisUnitsToEnterprise(ven_jsid,
                                        [staticAnalysisUnitId, dynamicAnalysisUnitId])

        sandbox_id = sandbox.getCurrentSandboxIdByAppId(ent_jsid, app.appId)
        if si is None:
            si = StaticScanInfo(staticAppVerId, staticAnalysisId,
                                staticAnalysisUnitId, sandbox_id)
        if si_dynamic is None:
            si_dynamic = DynamicScanInfo(dynamicAppVerId, dynamicAnalysisId,
                                         dynamicAnalysisUnitId, sandbox_id)

        app_info = AppInfo(app, si, si_dynamic, si_manual)
        custom_sevs = policymgr.get_policy_custom_severities(ent_jsid,
                                                             policy.policyId)
        cwes = dwrmethods.getUserVisibleCWEs(ent_jsid)

        self.verify_cots_report(ent_jsid, accountId, app_info, policy,
                                custom_sevs, cwes)
        self.verify_html_report(ven_jsid, accountId, app_info, custom_sevs, cwes)
        self.verify_report(ven_jsid, accountId, app_info, policy, custom_sevs,
                           cwes)

    @BrowserTest
    @DwrSessionProvider("external","internal")
    def test_dynamicmp_work_flow(self):
        """
        Test case 5: Dynamic MP work flow.
        """
        ext_session = self.external_session
        account_id = ext_session.loginAccount.accountId
        site_list = files.VALID_DYNAMICMP_SITELIST
        target_url = "http://rome.veracode.local/plugintest/"
        si_static = StaticScanInfo('', '', '', '')
        si_manual = None
        dynamicmp_info = scans.fetch_dynamicmp_scan(self.internal_session,
                                              account_id,
                                   (self.app_name+"10"),
                                   site_list, files.RESULTS_90,
                                   self.config.db_conn_str, target_url)

        policy = self.configure_policy(ext_session, self.app_name,
                                       custom_sevs=[self.dynamic_custom_sev])
        app_name = self.app_name + "MP7"
        app_info = self.configure_app(ext_session, app_name, policy)

        dynamicmp_action_pg = pages.DynamicMPStatusAction(self.browser)
        self.browser_login(self.internal_session)
        path = self.config.host + dynamicmp_action_pg.view_path(
            dynamicmp_info.app_id, dynamicmp_info.app_ver_id,
            dynamicmp_info.analysis_unit_id, dynamicmp_info.dynamicmp_job_id )
        analysisUnit = analysis.getAnalysisUnit(self.internal_session,
                                           dynamicmp_info.analysis_unit_id)

        if (analysisUnit.scanStatusId != ScanStatus.PENDINGINTERNALREVIEW
        or analysisUnit.scanStatusId != ScanStatus.RESULTSREADY):
            self.browser.get(path)
            time.sleep(10)
            # upload_dynamicmp = services.DynamicMP(self.browser)
            # upload_dynamicmp.upload_results(files.RESULTS_90)

            analysisUnit = analysis.getAnalysisUnit(self.internal_session,
                                               dynamicmp_info.analysis_unit_id)
        dynamicmp_action_pg.logout()

        if analysisUnit.scanStatusId == ScanStatus.PENDINGINTERNALREVIEW:
            analysis.publishAnalysis(self.internal_session,
                                     dynamicmp_info.analysis_unit_id)

        execunit_vers = analysis.getExecUnitVerIds(self.internal_session,
                                                   dynamicmp_info
                                                   .app_ver_id)

        dynamicmp.linktoApp(self.internal_session,
                            dynamicmp_info.dynamicmp_job_id, execunit_vers[0],
                            policy.policyGroupId, app_name, app_info.app.appId,
                            target_url, BusinessCriticality.VERYHIGH)

        si_dynamic = scans.fetch_dynamic_scan(ext_session, app_info.app, False)
        app_info = AppInfo(app_info.app, si_dynamic, si_static, si_manual)
        custom_sevs = policymgr.get_policy_custom_severities(ext_session,
                                                             policy.policyId)
        cwes = dwrmethods.getUserVisibleCWEs(ext_session)

        self.verify_html_report(ext_session, account_id, app_info,
                                custom_sevs, cwes)
        self.verify_report(ext_session, account_id, app_info, policy,
                           custom_sevs, cwes)

    def verify_report(self, jsid, account_id, app_info, policy, custom_sevs, cwes):
        self.detailedreport_pg = pages.ViewReportsDetailedReportPage(self.browser)
        path = self.config.host + self.detailedreport_pg.view_path(account_id,
                                    app_info.app.appId,
                                    app_info.static_scan_info.app_ver_id,
                                    app_info.static_scan_info.analysis_id,
                                    app_info.static_scan_info.analysis_unit_id,
                                    app_info.dynamic_scan_info.analysis_unit_id if app_info.dynamic_scan_info else '',
                                    sandbox_id = app_info.static_scan_info.sandbox_id)
        self.browser_login(jsid)
        self.browser.get(path)
        time.sleep(5)
        report = self.download_report("Detailed Veracode Report (PDF)")
        self.verify_pdf_report(jsid, policy, app_info, report, 3, custom_sevs,
                               cwes)
        report = self.download_report("Summary Veracode Report (PDF)")
        self.verify_pdf_report(jsid, policy, app_info, report, 3, custom_sevs,
                               cwes)


    def verify_html_report(self, jsid, accountId, app_info, custom_sevs, cwes):
        actual_headers = ["CWE ID and Name","Veracode Severity",
                          "Custom Severity"]
        
        self.browser_login(jsid)
        self.navigate_to_policy_ctrl(accountId, app_info)
        try:
            headers, sev_infos = self.report_pg.get_custom_severities_status()
        except NoSuchElementException:
            self.fail("Custom Severities section is not displaying")
          
        self.assertTrue(set(actual_headers) == set(headers), "Some column \
                                                headers are not displaying")

        for sev_dict in sev_infos:
            for custom_sev in custom_sevs:
                if str(custom_sev.CWEId) in sev_dict:
                    self.assertTrue(str(custom_sev.severity)+" - "+
                        IssueSeverity.getDesc(custom_sev.severity) in sev_infos[sev_dict])
                    for cwe in cwes:
                        if custom_sev.CWEId == cwe.commonWeaknessEnumerationId :
                            mapped_cwe = cwe
                    self.assertTrue(str(mapped_cwe.baseSeverity)+" - "+
                        IssueSeverity.getDesc(mapped_cwe.baseSeverity) in sev_infos[sev_dict])

        self.report_pg.logout()
              
    def verify_cots_report(self, jsid, accountId, app_info, policy, custom_sevs, cwes):
        browser = self.browser
        self.cr = pages.CotsReportPage(browser)
        report_url = self.config.host + self.cr.view_path(accountId,  app_info.app.appId,
                                                     app_info.static_scan_info.app_ver_id,
                                                     app_info.static_scan_info.analysis_id,
                    app_info.static_scan_info.analysis_unit_id)
        self.browser_login(jsid)
        browser.get(report_url)
        time.sleep(5)
        try:
            self.cr.click_download_reports()
            time.sleep(25)
        except NoSuchElementException as e:
            errmsg = "%s - COTS Report page did not load properly." % str(e)
            self.fail(msg=errmsg)
        downloaded_report = self.retrieve_report()
        # report = files.DOWNLOADS + os.path.sep + str(downloaded_report)
        self.verify_pdf_report(jsid, policy, app_info, downloaded_report, 4, custom_sevs, cwes)
        self.cr.logout()
        
    
    def configure_app(self, session, app_name=None, policy=None, static=False,
                      dynamicDs=False, manual=False, cots=False):
        """
        Configure the static scan for the tests.

        This uses the custom static_custom_sev on this instance.

        :param session: DwrSession used to configure the app, policy, and static scan.
        :param app_name: App name to be used when creating or fetching the app
        :param policy: If specified, this policy will be used for the app.
        :parma static: If True a Static scan will be configured.
        :param dynamic: If True a DynamicDS scan will be configured.
        :param manual: If True a manual scan will be configured
        
        :return: AppInfo instance.
        """
        policyGroupId = policy.policyGroupId if policy else 1
        
        if not app_name:
            app_name = "%s-app" % (self.current_name(append_ts=False),)

        if cots:
            app = self.fetch_app(session, app_name, policyGroupId=policyGroupId,
            enterpriseAccountId=self.external_session.loginAccount.accountId)
        else:
            app = self.fetch_app(session, app_name,
                policyGroupId=policyGroupId)
        
        static_info = None
        dynamic_info = None
        man_info = None
        
        if static:
            static_info = scans.fetch_static_scan(self.external_session, app,
                modules=[files.JAVASCANS], reset=True)
            
        if dynamicDs:
            dynamic_info = scans.fetch_dynamic_scan(session, app,
                            target_url="http://rome.veracode.local/plugintest")

        if manual:
            man_info = scans.fetch_manual_scan(session, app, results=files.RESULTS)

        app_info = AppInfo(app, static_info, dynamic_info, man_info)
        return app_info
        
    def configure_policy(self, session, policy_name=None, custom_sevs=None):
        """
        Configure a policy to be used for the test.

        Uses the format current_name()-policy for the policy name.

        :param session: DwrSession used to fetch the policy.
        :param policy_name: The name to use for the policy, self.current_name()-policy is used if
            this value is None.
        :param custom_sevs: List of custom_severities to be set on the policy.

        :return: The policy returned from fetch_policy
        """
        if not policy_name:
            policy_name = "%s-policy" % (self.current_name(),)

        policy = policymgr.fetch_policy(self.external_session, policy_name)
        if not policy:
            raise ValueError("Policy %s unable to be fetched." % (policy_name,))

        policyId = policymgr.specifyCustomSeverities(self.external_session,
                                                     policy, custom_sevs)
        policy.policyId = policyId
        return policy
    
    def publish_app_scans(self, session, app_info):
        '''
        Publishes the scans in the app.
        
        :param session: DwrSession used to publish the scans.
        :param app_info: An instance of AppInfo named tuple.
        '''
        if app_info.static_scan_info:
            self._publish(session, app_info.static_scan_info.analysis_unit_id)
            
        if app_info.dynamic_scan_info:
            self._publish(session, app_info.dynamic_scan_info.analysis_unit_id)
        
        if app_info.manual_scan_info:
            self._publish(session, app_info.manual_scan_info.analysis_unit_id)
        
    def _publish(self, session, analysis_unit_id):
        if not analysis.isPublished(session, analysis_unit_id):
            analysis.publishAnalysis(session, analysis_unit_id)
            analysis.waitForPublish(session, analysis_unit_id)
    
    def navigate_to_policy_ctrl(self, account_id, app_info):
        self.report_pg = pages.ViewReportsDetailedReportPage(self.browser)
        path = self.config.host + self.report_pg.view_path(account_id,
                app_info.app.appId, app_info.static_scan_info.app_ver_id,
                app_info.static_scan_info.analysis_id,
                static_analysis_unit_id=app_info.static_scan_info.analysis_unit_id,
                dynamic_analysis_unit_id=app_info.dynamic_scan_info.analysis_unit_id,
                sandbox_id=app_info.static_scan_info.sandbox_id)
        self.browser.get(path)
        time.sleep(10)
        self.report_pg.click_policy_control_tab()
        time.sleep(10)
        
    def download_report(self, report_type):
        self.detailedreport_pg.click_download_reports()
        self.detailedreport_pg.download_report_by_type(report_type)
        time.sleep(25)
        report = self.retrieve_report()
        downloaded_report = os.path.join(files.DOWNLOADS, report)
        return downloaded_report
        
    def verify_pdf_report(self, jsid, policy, app_info, report, page, custom_sevs,
                          cwes):
        downloaded_report_file = file(report, "rb")
        pdf = pyPdf.PdfFileReader(downloaded_report_file) 
        policy_eval_pg = pdf.getPage(page).extractText()
        downloaded_report_file.close()
        os.remove(report)
                                    
        matched = re.match(r'(.*)Remediation(.*)Scan(.*)Passed(.*)Veracode',
                           policy_eval_pg, re.M|re.I)
        if not (matched == None):
            self.assertTrue("Custom Severities" in matched.group(2),
                            "Name of the account is not right")
            self.assertTrue("CWE ID and NameVeracode SeverityCustom "
                            "Severity" \
            in matched.group(4))
            
            for custom_sev in custom_sevs:
                severity = str(custom_sev.severity)+" - "+\
                           IssueSeverity.getDesc(custom_sev.severity)
                self.assertTrue(severity in matched.group(4))
                for cwe in cwes:
                    if custom_sev.CWEId == cwe.commonWeaknessEnumerationId :
                        mapped_cwe = cwe
                        self.assertTrue(str(custom_sev.CWEId) in matched.group(4))
                        self.assertTrue(cwe.name.replace(" ","") in
                                        matched.group(4).replace(" ",""))
                        base_severity = str(mapped_cwe.baseSeverity)+" - "+\
                                    IssueSeverity.getDesc(mapped_cwe.baseSeverity)
                        self.assertTrue(base_severity in matched.group(4))
        
    def retrieve_report(self):
        downloaded_files = glob.glob('{root}/*.pdf'.format(root=files.DOWNLOADS))
        # Get the latest file by checking the modification time.
        latest_file = max(downloaded_files, key=os.path.getctime)
        return latest_file