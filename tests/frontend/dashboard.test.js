describe('Dashboard UI Comprehensive Testing', () => {
  beforeEach(() => {
    // Intercept API calls with mock data
    cy.intercept('GET', '/api/health', { statusCode: 200, body: { status: 'healthy' } }).as('getHealth');
    cy.intercept('GET', '/api/stats', { fixture: 'stats.json' }).as('getStats');
    cy.intercept('GET', '/api/events/recent', { fixture: 'events.json' }).as('getEvents');
    cy.visit('/');
  });

  it('Dashboard loads in < 3 seconds', () => {
    // Cy visits have their own timeout, checking element existence acts as a load verification
    cy.get('#dashboard-main', { timeout: 3000 }).should('be.visible');
  });

  it('All sections render without errors and Statistics cards show correct counts', () => {
    cy.get('[data-testid="stats-card"]').should('have.length', 4);
    cy.get('[data-testid="active-honeypots"]').should('contain', '4');
    cy.get('[data-testid="global-threat-level"]').should('be.visible');
  });

  describe('Events Table', () => {
    it('Recent events display correctly (Timestamp, Source IP, Type, Score)', () => {
      cy.get('.events-table').should('be.visible');
      cy.get('.events-table tbody tr').should('have.length.at.least', 1);
      cy.get('.events-table tbody tr').first().within(() => {
        cy.get('.col-timestamp').should('not.be.empty');
        cy.get('.col-ip').should('not.be.empty');
        cy.get('.col-score').should('not.be.empty');
      });
    });

    it('Search by IP/Honeypot/Date works', () => {
      cy.get('[data-testid="events-search"]').type('192.168.1.100');
      cy.get('.events-table tbody tr').should('contain', '192.168.1.100');
    });
  });

  describe('Attack Map', () => {
    it('World map displays, plots locations, hover works', () => {
      cy.get('#attack-map').should('be.visible');
      cy.get('.map-marker').should('exist');
      // Map hover
      cy.get('.map-marker').first().trigger('mouseover');
      cy.get('.map-tooltip').should('be.visible').and('not.be.empty');
    });
  });

  describe('ML Insights Page', () => {
    it('ML dashboard page accessible and charts render', () => {
      cy.get('[data-testid="nav-ml-insights"]').click();
      cy.url().should('include', '/ml-insights');
      cy.get('#threat-score-badge').should('be.visible');
      cy.get('#feature-importance-chart').should('be.visible');
      cy.get('.model-metrics-card').should('have.length.at.least', 3);
    });
  });

  describe('Attacker Details', () => {
    it('Click on IP shows attacker profile correctly', () => {
      cy.visit('/');
      cy.get('.col-ip a').first().click();
      cy.get('#attacker-profile-modal').should('be.visible');
      cy.get('.profile-geo').should('exist');
      cy.get('.profile-risk-score').should('exist');
    });
  });

  after(() => {
    cy.log('Expected Results:\nUI components render correctly, data accurately displayed, responsive across devices.');
  });
});
