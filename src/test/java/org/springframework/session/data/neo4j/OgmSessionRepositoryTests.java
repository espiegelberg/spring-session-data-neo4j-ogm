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

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Mock
	private Session session;

	@Mock
	private Transaction transaction;
	
	@Mock
	private SessionFactory sessionFactory;
	
	private OgmSessionRepository repository;
	
	@Before
	public void setUp() {
		this.repository = new OgmSessionRepository(this.sessionFactory);
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
		
		assertThat(session.isNew()).isTrue();
		assertThat(session.getMaxInactiveInterval())
				.isEqualTo(new MapSession().getMaxInactiveInterval());
		verifyZeroInteractions(this.sessionFactory);
	}

	@Test
	public void createSessionCustomMaxInactiveInterval() throws Exception {
		int interval = 1;
		this.repository.setDefaultMaxInactiveInterval(interval);

		OgmSessionRepository.OgmSession session = this.repository
				.createSession();

		assertThat(session.isNew()).isTrue();
		assertThat(session.getMaxInactiveInterval()).isEqualTo(Duration.ofSeconds(interval));
		verifyZeroInteractions(this.sessionFactory);
	}

	@Test
	public void saveNewWithoutAttributes() {
		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);

		OgmSessionRepository.OgmSession session = this.repository
				.createSession();

		this.repository.save(session);

		assertThat(session.isNew()).isFalse();
		assertThat(session).isNotNull();
		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
		verifyNoMoreInteractions(this.sessionFactory);
	}

	@Test
	public void saveNewWithAttributes() {		
		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);
		
		OgmSessionRepository.OgmSession session = this.repository
				.createSession();
		session.setAttribute("testName", "testValue");

		assertThat(session.isNew()).isTrue();
		
		this.repository.save(session);

		assertThat(session.isNew()).isFalse();

		assertThat(session).isNotNull();
		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.CREATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));		
	}

	@Test
	public void saveUpdatedAttributes() {
		
		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);
		
		List<Map<String, Object>> r = new ArrayList<>();
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		
		OgmSessionRepository.OgmSession session = this.repository
				.createSession();
		
		session.setAttribute("testName", "testValue");

		this.repository.save(session);

		assertThat(session.isNew()).isFalse();

		String expectedQuery = OgmSessionRepository.CREATE_SESSION_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
		verifyNoMoreInteractions(this.sessionFactory);
		
		session.setAttribute("testName", "testValue2");

		this.repository.save(session);
		
		assertThat(session).isNotNull();
		verify(this.sessionFactory, times(2)).openSession(); 
		verify(this.session, times(2)).beginTransaction();
		verify(this.transaction, times(2)).commit();
		verify(this.transaction, times(2)).close();
		verifyNoMoreInteractions(this.sessionFactory);
		
		expectedQuery = "match (n:SPRING_SESSION) where n.sessionId={sessionId} set n.lastAccessedTime={lastAccessedTime},n.attribute_testName={attribute_testName},n.sessionId={sessionId},n.maxInactiveInterval={maxInactiveInterval}";
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));
		
	}

//	@Test
//	public void saveUpdatedLastAccessedTime() {
//		OgmSessionRepository.OgmSession session = this.repository.new JdbcSession(
//				new MapSession());
//		session.setLastAccessedTime(Instant.now());
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		
//		verify(this.sessionFactory, times(1)).update(
//				and(startsWith("UPDATE"), contains("LAST_ACCESS_TIME")),
//				isA(PreparedStatementSetter.class));
//	}
//
//	@Test
//	public void saveUnchanged() {
//		OgmSessionRepository.OgmSession session = this.repository.new JdbcSession(
//				new MapSession());
//
//		this.repository.save(session);
//
//		assertThat(session.isNew()).isFalse();
//		verifyZeroInteractions(this.sessionFactory);
//	}

	@Test
	public void getSessionNotFound() {

		String sessionId = "testSessionId";

		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);
		
		List<Map<String, Object>> r = new ArrayList<>();
		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		OgmSessionRepository.OgmSession session = this.repository
				.getSession(sessionId);

		assertThat(session).isNull();
		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
		verifyNoMoreInteractions(this.sessionFactory);
	}

	@Test
	public void getSessionFound() {
		
		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);
		
		List<Map<String, Object>> r = new ArrayList<>();
		
		String attributeName = "name";
		String attributeValue = "Elizabeth";
		
		Map<String, Object> data = new HashMap<>();
		NodeModel nodeModel = new NodeModel();
		Map<String, Object> properties = new HashMap<>();
		long now = new Date().getTime();
		properties.put(OgmSessionRepository.CREATION_TIME, now);
		properties.put(OgmSessionRepository.LAST_ACCESS_TIME, now);
		properties.put(OgmSessionRepository.MAX_INACTIVE_INTERVAL, 30);		
		byte attributeValueBytes[] = this.repository.serialize(attributeValue);
		
		properties.put(OgmSessionRepository.ATTRIBUTE_KEY_PREFIX + attributeName, attributeValueBytes);
		
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
		
		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
		verifyNoMoreInteractions(this.sessionFactory);
	}
	
	@Test
	public void getSessionExpired() {
		MapSession expired = new MapSession();		
		long a = MapSession.DEFAULT_MAX_INACTIVE_INTERVAL_SECONDS + 1;
		Instant b = Instant.now().minusSeconds(a);		
		expired.setLastAccessedTime(b);
		long c = b.toEpochMilli();
		
		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);

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

		//verify(this.sessionFactory, times(1)).update(startsWith("DELETE"), eq(expired.getId()));
		//verify(this.repository, times(1)).delete(expiredSession.getId());
		
		verify(this.sessionFactory, times(2)).openSession(); 
		verify(this.session, times(2)).beginTransaction();
		verify(this.transaction, times(2)).commit();
		verify(this.transaction, times(2)).close();
		verifyNoMoreInteractions(this.sessionFactory);
	}

	@Test
	public void delete() {
		
		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);

		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		queryStatisticsModel.setNodes_deleted(1);
		List<Map<String, Object>> r = new ArrayList<>();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);

		String sessionId = "testSessionId";
		this.repository.delete(sessionId);
		
		//verify(this.sessionFactory, times(1)).update(startsWith("DELETE"), eq(sessionId));
		
		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
		verifyNoMoreInteractions(this.sessionFactory);
	}

//	@Test
//	public void findByIndexNameAndIndexValueUnknownIndexName() {
//		String indexValue = "testIndexValue";
//
//		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
//				.findByIndexNameAndIndexValue("testIndexName", indexValue);
//
//		assertThat(sessions).isEmpty();
//		verifyZeroInteractions(this.sessionFactory);
//	}
//
//	@Test
//	public void findByIndexNameAndIndexValuePrincipalIndexNameNotFound() {
//		String principal = "username";
//		given(this.sessionFactory.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(Collections.emptyList());
//
//		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
//				.findByIndexNameAndIndexValue(
//						FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
//						principal);
//
//		assertThat(sessions).isEmpty();
//		
//		verify(this.sessionFactory, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//	}
//
//	@Test
//	public void findByIndexNameAndIndexValuePrincipalIndexNameFound() {
//		String principal = "username";
//		Authentication authentication = new UsernamePasswordAuthenticationToken(principal,
//				"notused", AuthorityUtils.createAuthorityList("ROLE_USER"));
//		List<MapSession> saved = new ArrayList<>(2);
//		MapSession saved1 = new MapSession();
//		saved1.setAttribute(SPRING_SECURITY_CONTEXT, authentication);
//		saved.add(saved1);
//		MapSession saved2 = new MapSession();
//		saved2.setAttribute(SPRING_SECURITY_CONTEXT, authentication);
//		saved.add(saved2);
//		given(this.sessionFactory.query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class)))
//				.willReturn(saved);
//
//		Map<String, OgmSessionRepository.OgmSession> sessions = this.repository
//				.findByIndexNameAndIndexValue(
//						FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
//						principal);
//
//		assertThat(sessions).hasSize(2);
//		
//		verify(this.sessionFactory, times(1)).query(isA(String.class),
//				isA(PreparedStatementSetter.class), isA(ResultSetExtractor.class));
//	}

	@Test
	public void cleanupExpiredSessions() {

		given(this.sessionFactory.openSession()).willReturn(session);		
		given(session.beginTransaction()).willReturn(transaction);

		QueryStatisticsModel queryStatisticsModel = new QueryStatisticsModel();
		queryStatisticsModel.setNodes_deleted(1);
		List<Map<String, Object>> r = new ArrayList<>();
		Result result = new QueryResultModel(r, queryStatisticsModel);
		given(this.session.query(isA(String.class), isA(Map.class))).willReturn(result);
		
		this.repository.cleanUpExpiredSessions();

		verify(this.sessionFactory, times(1)).openSession(); 
		verify(this.session, times(1)).beginTransaction();
		verify(this.transaction, times(1)).commit();
		verify(this.transaction, times(1)).close();
		verifyNoMoreInteractions(this.sessionFactory);
		
		String expectedQuery = OgmSessionRepository.DELETE_SESSIONS_BY_LAST_ACCESS_TIME_QUERY.replace("%LABEL%", OgmSessionRepository.DEFAULT_LABEL);
		verify(this.session, times(1)).query(eq(expectedQuery), isA(Map.class));		
	}

}
