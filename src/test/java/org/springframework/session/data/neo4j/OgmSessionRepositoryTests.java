/*
 * Copyright 2014-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.session.data.neo4j;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.neo4j.ogm.model.Result;
import org.neo4j.ogm.response.model.NodeModel;
import org.neo4j.ogm.response.model.QueryResultModel;
import org.neo4j.ogm.response.model.QueryStatisticsModel;
import org.neo4j.ogm.session.Session;
import org.neo4j.ogm.session.SessionFactory;
import org.neo4j.ogm.transaction.Transaction;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests for {@link OgmSessionRepository}.
 *
 * @author Eric Spiegelberg
 * @author Vedran Pavic
 * @since 1.2.0
 */
@RunWith(MockitoJUnitRunner.class)
public class OgmSessionRepositoryTests {

	private static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

	@Mock
	private Session session;

	@Mock
	private Transaction transaction;
	
	@Mock
	private SessionFactory sessionFactory;
	
	private OgmSessionRepository repository;
	
	@Rule
	public ExpectedException thrown = ExpectedException.none();
	
	@Before
	public void setUp() {
		this.repository = new OgmSessionRepository(this.sessionFactory);
		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);
	}

	@Test
	public void constructorSessionFactory() {
		OgmSessionRepository repository = new OgmSessionRepository(this.sessionFactory);

		assertThat(ReflectionTestUtils.getField(repository, "sessionFactory"))
				.isNotNull();
	}

	@Test
	public void constructorNullSessionFactory() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Property 'sessionFactory' must not be null");

		new OgmSessionRepository(null);
	}

	@Test
	public void setLabelNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Label must not be empty");

		this.repository.setLabel(null);
	}

	@Test
	public void setLabelEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Label must not be empty");

		this.repository.setLabel(" ");
	}

	@Test
	public void setCreateSessionQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setCreateSessionQuery(null);
	}

	@Test
	public void setCreateSessionQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setCreateSessionQuery(" ");
	}

	@Test
	public void setGetSessionQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setGetSessionQuery(null);
	}

	@Test
	public void setGetSessionQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setGetSessionQuery(" ");
	}

	@Test
	public void setUpdateSessionQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setUpdateSessionQuery(null);
	}

	@Test
	public void setUpdateSessionQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setUpdateSessionQuery(" ");
	}

	@Test
	public void setDeleteSessionQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setDeleteSessionQuery(null);
	}

	@Test
	public void setDeleteSessionQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setDeleteSessionQuery(" ");
	}

	@Test
	public void setListSessionsByPrincipalNameQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setListSessionsByPrincipalNameQuery(null);
	}

	@Test
	public void setListSessionsByPrincipalNameQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setListSessionsByPrincipalNameQuery(" ");
	}

	@Test
	public void setDeleteSessionsByLastAccessTimeQueryNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setDeleteSessionsByLastAccessTimeQuery(null);
	}

	@Test
	public void setDeleteSessionsByLastAccessTimeQueryEmpty() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("Query must not be empty");

		this.repository.setDeleteSessionsByLastAccessTimeQuery(" ");
	}

	@Test
	public void setConversionServiceNull() {
		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("conversionService must not be null");

		this.repository.setConversionService(null);
	}

	@Test
	public void createSessionDefaultMaxInactiveInterval() throws Exception {
		
		OgmSessionRepository.OgmSession session = this.repository.createSession();
		
		assertThat(session).isNotNull();
		assertThat(session.isNew()).isTrue();
		assertThat(session.getMaxInactiveInterval())
				.isEqualTo(new MapSession().getMaxInactiveInterval());

		verifyCounts(0);
		verifyZeroInteractions(this.sessionFactory);
	}

	@Test
	public void createSessionCustomMaxInactiveInterval() throws Exception {
		int interval = 1;
		this.repository.setDefaultMaxInactiveInterval(interval);

		OgmSessionRepository.OgmSession session = this.repository
				.createSession();

		assertThat(session).isNotNull();
		assertThat(session.isNew()).isTrue();
		assertThat(session.getMaxInactiveInterval()).isEqualTo(Duration.ofSeconds(interval));
		
		verifyCounts(0);
		verifyZeroInteractions(this.sessionFactory);
	}

	@Test
	public void saveNewWithoutAttributes() {

		OgmSessionRepository.OgmSession session = this.repository
				.createSession();

		this.repository.save(session);

		assertThat(session).isNotNull();
		assertThat(session.isNew()).isFalse();

		String expectedQuery = OgmSessionRepository.CREATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);		
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));

		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
	}

	@Test
	public void saveNewWithAttributes() {		
		
		OgmSessionRepository.OgmSession session = this.repository
				.createSession();
		session.setAttribute("testName", "testValue");

		assertThat(session.isNew()).isTrue();
		
		this.repository.save(session);

		assertThat(session).isNotNull();
		assertThat(session.isNew()).isFalse();

		String expectedQuery = OgmSessionRepository.CREATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		
		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
	}

	@Test
	public void saveUpdatedAttributes() {
		List<Map<String, Object>> r = new ArrayList<>();
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
				
		OgmSessionRepository.OgmSession session = this.repository
				.createSession();
		
		session.setAttribute("testName", "testValue");

		this.repository.save(session);

		assertThat(session).isNotNull();
		assertThat(session.isNew()).isFalse();

		String expectedQuery = OgmSessionRepository.CREATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		
		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
		
		session.setAttribute("testName", "testValue2");

		this.repository.save(session);
		
		assertThat(session).isNotNull();
		verifyCounts(2);
		verifyNoMoreInteractions(this.sessionFactory);

		expectedQuery = OgmSessionRepository.UPDATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		expectedQuery = expectedQuery.replaceAll("%PROPERTIES_TO_UPDATE%", "n.lastAccessedTime={lastAccessedTime},n.attribute_testName={attribute_testName},n.principalName={principalName},n.sessionId={sessionId},n.maxInactiveInterval={maxInactiveInterval}");
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));

	}

	@Test
	public void saveUpdatedLastAccessedTime() {
		OgmSessionRepository.OgmSession session = this.repository
				.createSession();
		session.setLastAccessedTime(Instant.now());

		assertThat(session).isNotNull();
		assertThat(session.isNew()).isTrue();
		
		this.repository.save(session);
		
		assertThat(session.isNew()).isFalse();		
		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.CREATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		expectedQuery = expectedQuery.replaceAll("%PROPERTIES_TO_UPDATE%", "n.lastAccessedTime={lastAccessedTime},n.attribute_testName={attribute_testName},n.principalName={principalName},n.sessionId={sessionId},n.maxInactiveInterval={maxInactiveInterval}");
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		
		session.setAttribute("updated", true);
		this.repository.save(session);

		assertThat(session.isNew()).isFalse();
		verifyCounts(2);
		verifyNoMoreInteractions(this.sessionFactory);

		expectedQuery = OgmSessionRepository.UPDATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		expectedQuery = expectedQuery.replaceAll("%PROPERTIES_TO_UPDATE%", "n.lastAccessedTime={lastAccessedTime},n.principalName={principalName},n.sessionId={sessionId},n.maxInactiveInterval={maxInactiveInterval},n.attribute_updated={attribute_updated}");
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		
	}

	// TODO: Should saving an unchanged Session update the last access time? I think so
	@Test
	public void saveUnchanged() {
		OgmSessionRepository.OgmSession session = this.repository
				.createSession();

		assertThat(session).isNotNull();
		assertThat(session.isNew()).isTrue();
		
		this.repository.save(session);

		assertThat(session).isNotNull();
		assertThat(session.isNew()).isFalse();
		
		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.CREATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		expectedQuery = expectedQuery.replaceAll("%PROPERTIES_TO_UPDATE%", "n.lastAccessedTime={lastAccessedTime},n.attribute_testName={attribute_testName},n.principalName={principalName},n.sessionId={sessionId},n.maxInactiveInterval={maxInactiveInterval}");
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		
		this.repository.save(session);
		
		assertThat(session.isNew()).isFalse();
		verifyCounts(2);
		verifyZeroInteractions(this.sessionFactory);
		verifyNoMoreInteractions(this.sessionFactory);
		
		expectedQuery = OgmSessionRepository.UPDATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		expectedQuery = expectedQuery.replaceAll("%PROPERTIES_TO_UPDATE%", "n.lastAccessedTime={lastAccessedTime},n.principalName={principalName},n.sessionId={sessionId},n.maxInactiveInterval={maxInactiveInterval}");
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
	}

	@Test
	public void getSessionNotFound() {

		String sessionId = "testSessionId";

		List<Map<String, Object>> r = new ArrayList<>();
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		OgmSessionRepository.OgmSession session = this.repository
				.getSession(sessionId);

		assertThat(session).isNull();
		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.GET_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		
	}

	@Test
	public void getSessionFound() {
		List<Map<String, Object>> r = new ArrayList<>();
		String attributeName = "name";
		String attributeValue = "Elizabeth";
		
		Map<String, Object> data = new HashMap<>();
		NodeModel nodeModel = new NodeModel();
		Map<String, Object> properties = new HashMap<>();
		long now = new Date().getTime();
		properties.put(OgmSessionRepository.CREATION_TIME, now);
		properties.put(OgmSessionRepository.LAST_ACCESS_TIME, now);
		properties.put(OgmSessionRepository.MAX_INACTIVE_INTERVAL, Integer.MAX_VALUE);
		
		byte attributeValueBytes[] = this.repository.serialize(attributeValue);		
		properties.put(OgmSessionRepository.ATTRIBUTE_KEY_PREFIX + attributeName, attributeValueBytes);		
//		properties.put(OgmSessionRepository.ATTRIBUTE_KEY_PREFIX + attributeName, attributeValue);
		
		nodeModel.setProperties(properties);
		data.put("n", nodeModel);
		r.add(data);
		
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		MapSession saved = new MapSession();
		saved.setAttribute(attributeName, attributeValue);

		OgmSessionRepository.OgmSession session = this.repository
				.getSession(saved.getId());

		assertThat(session).isNotNull();
		
		assertThat(session.getId()).isEqualTo(saved.getId());
		assertThat(session.isNew()).isFalse();

		assertThat(session.<String>getAttribute(attributeName).orElse(null)).isEqualTo(attributeValue);
		
		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.GET_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
	}
	
	@Test
	public void getSessionExpired() {
		MapSession expired = new MapSession();		
		long a = MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS + 1;
		Instant b = Instant.now().minusSeconds(a);		
		expired.setLastAccessedTime(b);
		long c = b.toEpochMilli();

		NodeModel nodeModel = new NodeModel();
		Map<String, Object> properties = new HashMap<>();
		long now = new Date().getTime();
		
		properties.put(OgmSessionRepository.CREATION_TIME, 0L);
		properties.put(OgmSessionRepository.LAST_ACCESS_TIME, 100L);
		properties.put(OgmSessionRepository.MAX_INACTIVE_INTERVAL, 1);		
		nodeModel.setProperties(properties);
		
		Map<String, Object> data = new HashMap<>();
		data.put("n", nodeModel);
		
		List<Map<String, Object>> r = new ArrayList<>();		
		r.add(data);

		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);

		OgmSessionRepository.OgmSession session = this.repository
				.getSession(expired.getId());

		assertThat(session).isNull();		
		verifyCounts(2);
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.GET_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));

		expectedQuery = OgmSessionRepository.DELETE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
	}

	@Test
	public void delete() {
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		queryStatisticsModel.setNodes_deleted(1);
		List<Map<String, Object>> r = new ArrayList<>();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);

		String sessionId = "testSessionId";
		this.repository.delete(sessionId);
		
		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.DELETE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
	}

	@Test
	public void findByIndexNameAndIndexValueUnknownIndexName() {
		String indexValue = "testIndexValue";

		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
				.findByIndexNameAndIndexValue("testIndexName", indexValue);

		assertThat(sessions).isEmpty();
		verifyZeroInteractions(this.sessionFactory);
	}

	@Test
	public void findByIndexNameAndIndexValuePrincipalIndexNameNotFound() {
		List<Map<String, Object>> r = new ArrayList<>();
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		String principal = "username";

		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
				.findByIndexNameAndIndexValue(
						FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
						principal);

		assertThat(sessions).isEmpty();

		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.LIST_SESSIONS_BY_PRINCIPAL_NAME_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		
	}

	@Test
	public void findByIndexNameAndIndexValuePrincipalIndexNameFound() {
		
		List<MapSession> saved = new ArrayList<>(2);
		
		String principal = "username";
		Authentication authentication = new UsernamePasswordAuthenticationToken(principal,
				"notused", AuthorityUtils.createAuthorityList("ROLE_USER"));
		
		MapSession saved1 = new MapSession();
		saved1.setAttribute(SPRING_SECURITY_CONTEXT, authentication);
		saved.add(saved1);
		
		MapSession saved2 = new MapSession();
		saved2.setAttribute(SPRING_SECURITY_CONTEXT, authentication);
		saved.add(saved2);

		Map<String, Object> data1 = new HashMap<>();
		NodeModel nodeModel = new NodeModel();
		Map<String, Object> properties = new HashMap<>();
		long now = new Date().getTime();
		properties.put(OgmSessionRepository.SESSION_ID, "1");
		properties.put(OgmSessionRepository.CREATION_TIME, now);
		properties.put(OgmSessionRepository.LAST_ACCESS_TIME, now);
		properties.put(OgmSessionRepository.MAX_INACTIVE_INTERVAL, 30);
		nodeModel.setProperties(properties);
		data1.put("n", nodeModel);
		
		Map<String, Object> data2 = new HashMap<>();
		NodeModel nodeModel2 = new NodeModel();
		Map<String, Object> properties2 = new HashMap<>();
		long now2 = new Date().getTime();
		properties2.put(OgmSessionRepository.SESSION_ID, "2");
		properties2.put(OgmSessionRepository.CREATION_TIME, now2);
		properties2.put(OgmSessionRepository.LAST_ACCESS_TIME, now2);
		properties2.put(OgmSessionRepository.MAX_INACTIVE_INTERVAL, 30);
		nodeModel2.setProperties(properties2);		
		data2.put("n", nodeModel2);

		List<Map<String, Object>> r = new ArrayList<>();
		r.add(data1);
		r.add(data2);
		
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);

		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
				.findByIndexNameAndIndexValue(
						FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
						principal);

		assertThat(sessions).hasSize(2);

		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.LIST_SESSIONS_BY_PRINCIPAL_NAME_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
	}

	@Test
	public void cleanupExpiredSessions() {
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		queryStatisticsModel.setNodes_deleted(1);
		List<Map<String, Object>> r = new ArrayList<>();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		this.repository.cleanUpExpiredSessions();

		verifyCounts(1);
		verifyNoMoreInteractions(this.sessionFactory);

		String expectedQuery = OgmSessionRepository.DELETE_SESSIONS_BY_LAST_ACCESS_TIME_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
	}

	protected void verifyCounts(int count) {
		verify(this.transaction, times(count)).close();
		verify(this.transaction, times(count)).commit();
		verify(this.session, times(count)).beginTransaction();
		verify(this.sessionFactory, times(count)).openSession();
	}

}
