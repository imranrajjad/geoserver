/* (c) 2019 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.generatedgeometries.core.longitudelatitude;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.geotools.filter.visitor.DefaultFilterVisitor;
import org.opengis.filter.And;
import org.opengis.filter.Not;
import org.opengis.filter.Or;
import org.opengis.filter.PropertyIsBetween;

/** @author ImranR */
public class FilterCollector extends DefaultFilterVisitor {

    List<String> allFilters = new ArrayList<String>();

    @Override
    public Object visit(And filter, Object data) {
        allFilters.add(filter.toString());
        return super.visit(filter, data);
    }

    @Override
    public Object visit(Not filter, Object data) {
        allFilters.add(filter.toString());
        return super.visit(filter, data);
    }

    @Override
    public Object visit(Or filter, Object data) {
        allFilters.add(filter.toString());
        return super.visit(filter, data);
    }

    @Override
    public Object visit(PropertyIsBetween filter, Object data) {
        allFilters.add(filter.toString());
        return super.visit(filter, data);
    }

    public boolean hasAll(List<String> otherListOfFilters) {

        Collections.sort(allFilters);
        Collections.sort(otherListOfFilters);

        return this.allFilters.containsAll(otherListOfFilters);
    }
}
