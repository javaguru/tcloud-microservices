package com.jservlet;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;

import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import static org.junit.Assert.assertEquals;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = TcloudApplication.class)
public class TcloudApplicationTests {

	@Value("${local.server.port:8010}")
	private int port = 8010;

	@Test
	public void tcloudsLoads() {
        Tcloud[] entity = new TestRestTemplate().getForObject("http://localhost:" + port + "/tclouds-service", Tcloud[].class);
		assertEquals(Boolean.TRUE, entity.length > 0);
	}

	@Test
	public void tcloudLoads() {
		Tcloud[] entity = new TestRestTemplate().getForObject("http://localhost:" + port + "/tclouds-service?q=Test1", Tcloud[].class);
        assertEquals(Boolean.TRUE, entity[0] != null);
	}


}
