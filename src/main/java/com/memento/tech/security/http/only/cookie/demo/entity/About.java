package com.memento.tech.security.http.only.cookie.demo.entity;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class About {

    private final String name;

    private final String dateOfBirthTimestamp;

    private final String email;

    public About() {
        this.name = "Igor Stojanovic";
        this.dateOfBirthTimestamp = "30041994";
        this.email = "igor.stojanovic.nis@outlook.com";
    }

    public Map<String, String> getWorkExperience() {
        var result = new LinkedHashMap<String, String>();

        result.put("Feb 2021 - Jun 2023", "Junior Software Developer at Robert Bosch");
        result.put("Jun 2023 - Jan 2024", "Software Developer at Robert Bosch");
        result.put("Jan 2024 - now", "Software Developer at FIS (Fidelity Information Services)");
        result.put("Jun 2023 - now", "Software Developer at Memento Tech");

        return result;
    }

    public Map<String, String> getEducation() {
        var result = new LinkedHashMap<String, String>();

        result.put("2009 - 2013", "Surveyor - Technical school");
        result.put("2016 - 2020", "Engineer in computing and informatics - Kosovska Mitrovica");

        return result;
    }

    public List<String> getSkills() {
        var result = new LinkedList<String>();

        result.add("Java 17+");
        result.add("Kotlin");
        result.add("J2EE");
        result.add("Hibernate");
        result.add("JPA");
        result.add("JUnit, Mockito, WireMock");
        result.add("Postman");
        result.add("Maven/Gradle");
        result.add("Git");
        result.add("Jenkins");
        result.add("SAP Hybris");
        result.add("Apache SOLR");
        result.add("Keyclock, OAuth2, JWT");
        result.add("Javascript");
        result.add("React JS");
        result.add("Google API");
        result.add("CSS/SCSS");
        result.add("JQuery");

        return result;
    }
}
