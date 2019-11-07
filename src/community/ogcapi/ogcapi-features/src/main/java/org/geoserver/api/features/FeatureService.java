/* (c) 2019 Open Source Geospatial Foundation - all rights reserved
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.api.features;

import io.swagger.v3.oas.models.OpenAPI;
import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import javax.xml.namespace.QName;
import net.opengis.wfs20.Wfs20Factory;
import org.geoserver.api.*;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.FeatureTypeInfo;
import org.geoserver.config.GeoServer;
import org.geoserver.ows.kvp.TimeParser;
import org.geoserver.platform.ServiceException;
import org.geoserver.wfs.StoredQueryProvider;
import org.geoserver.wfs.WFSInfo;
import org.geoserver.wfs.request.FeatureCollectionResponse;
import org.geoserver.wfs.request.GetFeatureRequest;
import org.geoserver.wfs.request.Query;
import org.geotools.factory.CommonFactoryFinder;
import org.geotools.filter.text.ecql.ECQL;
import org.geotools.util.DateRange;
import org.opengis.feature.type.FeatureType;
import org.opengis.filter.Filter;
import org.opengis.filter.FilterFactory2;
import org.opengis.filter.expression.Literal;
import org.opengis.filter.expression.PropertyName;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/** Implementation of OGC Features API service */
@APIService(
    service = "Features",
    version = "1.0",
    landingPage = "ogc/features",
    serviceClass = WFSInfo.class
)
@RequestMapping(path = APIDispatcher.ROOT_PATH + "/features")
public class FeatureService {

    public static final String CORE = "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core";
    public static final String HTML = "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/html";
    public static final String GEOJSON =
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/geojson";
    public static final String GMLSF0 =
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/req/gmlsf0";
    public static final String GMLSF2 =
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/req/gmlsf2";
    public static final String OAS30 =
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/oas30";
    public static final String CQL_TEXT =
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/x-cql-text";
    public static final String CQL_JSON_OBJECT =
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/x-cql-json-object";
    public static final String CQL_JSON_ARRAY =
            "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/x-cql-json-array";

    public static String ITEM_ID = "OGCFeatures:ItemId";

    private static final FilterFactory2 FF = CommonFactoryFinder.getFilterFactory2();

    private final GeoServer geoServer;

    private TimeParser timeParser = new TimeParser();

    public FeatureService(GeoServer geoServer) {
        this.geoServer = geoServer;
    }

    public WFSInfo getService() {
        return geoServer.getService(WFSInfo.class);
    }

    private Catalog getCatalog() {
        return geoServer.getCatalog();
    }

    @GetMapping(name = "getLandingPage")
    @ResponseBody
    @HTMLResponseBody(templateName = "landingPage.ftl", fileName = "landingPage.html")
    public FeaturesLandingPage getLandingPage() {
        return new FeaturesLandingPage(getService(), getCatalog(), "ogc/features");
    }

    @GetMapping(
        path = "api",
        name = "getApi",
        produces = {
            OpenAPIMessageConverter.OPEN_API_VALUE,
            "application/x-yaml",
            MediaType.TEXT_XML_VALUE
        }
    )
    @ResponseBody
    @HTMLResponseBody(templateName = "api.ftl", fileName = "api.html")
    public OpenAPI api() {
        return new FeaturesAPIBuilder().build(getService());
    }

    @GetMapping(path = "collections", name = "getCollections")
    @ResponseBody
    @HTMLResponseBody(templateName = "collections.ftl", fileName = "collections.html")
    public CollectionsDocument getCollections() {
        return new CollectionsDocument(geoServer);
    }

    @GetMapping(path = "collections/{collectionId}", name = "describeCollection")
    @ResponseBody
    @HTMLResponseBody(templateName = "collection.ftl", fileName = "collection.html")
    public CollectionDocument collection(@PathVariable(name = "collectionId") String collectionId) {
        FeatureTypeInfo ft = getFeatureType(collectionId);
        CollectionDocument collection = new CollectionDocument(geoServer, ft);

        return collection;
    }

    @GetMapping(path = "collections/{collectionId}/queryables", name = "getQueryables")
    @ResponseBody
    @HTMLResponseBody(templateName = "queryables.ftl", fileName = "queryables.html")
    public QueryablesDocument queryables(@PathVariable(name = "collectionId") String collectionId)
            throws IOException {
        FeatureTypeInfo ft = getFeatureType(collectionId);
        return new QueryablesDocument(ft);
    }

    private FeatureTypeInfo getFeatureType(String collectionId) {
        // single collection
        FeatureTypeInfo featureType = getCatalog().getFeatureTypeByName(collectionId);
        if (featureType == null) {
            throw new ServiceException(
                    "Unknown collection " + collectionId,
                    ServiceException.INVALID_PARAMETER_VALUE,
                    "collectionId");
        }
        return featureType;
    }

    @GetMapping(path = "conformance", name = "getConformanceDeclaration")
    @ResponseBody
    public ConformanceDocument conformance() {
        List<String> classes = Arrays.asList(CORE, OAS30, HTML, GEOJSON, GMLSF0, CQL_TEXT);
        return new ConformanceDocument(classes);
    }

    @GetMapping(path = "collections/{collectionId}/items/{itemId:.+}", name = "getFeature")
    @ResponseBody
    @DefaultContentType(RFCGeoJSONFeaturesResponse.MIME)
    public FeaturesResponse item(
            @PathVariable(name = "collectionId") String collectionId,
            @RequestParam(name = "startIndex", required = false, defaultValue = "0")
                    BigInteger startIndex,
            @RequestParam(name = "limit", required = false) BigInteger limit,
            @RequestParam(name = "bbox", required = false) String bbox,
            @RequestParam(name = "time", required = false) String time,
            @PathVariable(name = "itemId") String itemId)
            throws Exception {
        return items(collectionId, startIndex, limit, bbox, time, null, null, itemId);
    }

    @GetMapping(path = "collections/{collectionId}/items", name = "getFeatures")
    @ResponseBody
    @DefaultContentType(RFCGeoJSONFeaturesResponse.MIME)
    public FeaturesResponse items(
            @PathVariable(name = "collectionId") String collectionId,
            @RequestParam(name = "startIndex", required = false, defaultValue = "0")
                    BigInteger startIndex,
            @RequestParam(name = "limit", required = false) BigInteger limit,
            @RequestParam(name = "bbox", required = false) String bbox,
            @RequestParam(name = "datetime", required = false) String datetime,
            @RequestParam(name = "filter", required = false) String filter,
            @RequestParam(name = "filter-lang", required = false) String filterLanguage,
            String itemId)
            throws Exception {
        // build the request in a way core WFS machinery can understand it
        FeatureTypeInfo ft = getFeatureType(collectionId);
        GetFeatureRequest request =
                GetFeatureRequest.adapt(Wfs20Factory.eINSTANCE.createGetFeatureType());
        Query query = request.createQuery();
        query.setTypeNames(Arrays.asList(new QName(ft.getNamespace().getURI(), ft.getName())));
        List<Filter> filters = new ArrayList<>();
        if (bbox != null) {
            filters.add(APIBBoxParser.toFilter(bbox));
        }
        if (datetime != null) {
            filters.add(buildTimeFilter(ft, datetime));
        }
        if (itemId != null) {
            filters.add(FF.id(FF.featureId(itemId)));
        }
        if (filter != null) {
            if (filterLanguage != null && !filterLanguage.equals("cql-text")) {
                throw new APIException(
                        "InvalidParameterValue",
                        "Unsupported filter language: " + filterLanguage,
                        HttpStatus.BAD_REQUEST);
            }
            filters.add(ECQL.toFilter(filter));
        }
        query.setFilter(mergeFiltersAnd(filters));
        request.setStartIndex(startIndex);
        request.setMaxFeatures(limit);
        request.setBaseUrl(APIRequestInfo.get().getBaseURL());
        request.getAdaptedQueries().add(query.getAdaptee());

        // run it
        FeaturesGetFeature gf = new FeaturesGetFeature(getService(), getCatalog());
        gf.setFilterFactory(FF);
        gf.setStoredQueryProvider(getStoredQueryProvider());
        FeatureCollectionResponse response = gf.run(request);

        // store information about single vs multi request
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute(ITEM_ID, itemId, RequestAttributes.SCOPE_REQUEST);
        }

        // build a response tracking both results and request to allow reusing the existing WFS
        // output formats
        return new FeaturesResponse(request.getAdaptee(), response);
    }

    private Filter buildTimeFilter(FeatureTypeInfo ft, String time)
            throws ParseException, IOException {
        Collection times = timeParser.parse(time);
        if (times.isEmpty() || times.size() > 1) {
            throw new ServiceException(
                    "Invalid time specification, must be a single time, or a time range",
                    ServiceException.INVALID_PARAMETER_VALUE,
                    "time");
        }

        List<Filter> filters = new ArrayList<>();
        Object timeSpec = times.iterator().next();
        for (String timeProperty : getTimeProperties(ft)) {
            PropertyName property = FF.property(timeProperty);
            Filter filter;
            if (timeSpec instanceof Date) {
                filter = FF.equals(property, FF.literal(timeSpec));
            } else if (timeSpec instanceof DateRange) {
                DateRange dateRange = (DateRange) timeSpec;
                Literal before = FF.literal(dateRange.getMinValue());
                Literal after = FF.literal(dateRange.getMaxValue());
                filter = FF.between(property, before, after);
            } else {
                throw new IllegalArgumentException("Cannot build time filter out of " + timeSpec);
            }

            filters.add(filter);
        }

        return mergeFiltersOr(filters);
    }

    private List<String> getTimeProperties(FeatureTypeInfo ft) throws IOException {
        FeatureType schema = ft.getFeatureType();
        return schema.getDescriptors()
                .stream()
                .filter(pd -> Date.class.isAssignableFrom(pd.getType().getBinding()))
                .map(pd -> pd.getName().getLocalPart())
                .collect(Collectors.toList());
    }

    private Filter mergeFiltersAnd(List<Filter> filters) {
        if (filters.isEmpty()) {
            return Filter.INCLUDE;
        } else if (filters.size() == 1) {
            return filters.get(0);
        } else {
            return FF.and(filters);
        }
    }

    private Filter mergeFiltersOr(List<Filter> filters) {
        if (filters.isEmpty()) {
            return Filter.EXCLUDE;
        } else if (filters.size() == 1) {
            return filters.get(0);
        } else {
            return FF.or(filters);
        }
    }

    private StoredQueryProvider getStoredQueryProvider() {
        return new StoredQueryProvider(getCatalog());
    }
}
