/* (c) 2020 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.config.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.urlchecker.GeoserverURLChecker;
import org.geoserver.security.urlchecker.GeoserverURLConfigService;
import org.geoserver.test.GeoServerSystemTestSupport;
import org.geotools.data.ows.URLCheckerFactory;
import org.junit.Before;
import org.junit.Test;

/** @author ImranR */
public class GeoserverURLCheckerTests extends GeoServerSystemTestSupport {

    static GeoserverURLConfigService configBean;

    @Before
    public void setUp() throws Exception {
        // instantiate bean
        configBean = GeoServerExtensions.bean(GeoserverURLConfigService.class);
        // verify
        assertNotNull(configBean);
        // verify SPI Factory has the bean registered
        assertFalse(URLCheckerFactory.getUrlCheckerList().isEmpty());
    }

    @Test
    public void testBasicReadWrite() throws Exception {
        GeoserverURLChecker checker = configBean.reload();
        assertNotNull(checker);
        // modify
        checker.setEnabled(true);
        checker = configBean.save();
        assertTrue(checker.isEnabled());
        assertTrue(URLCheckerFactory.getUrlCheckerList().size() == 1);
    }

    // TODO add regex validation tests

}
