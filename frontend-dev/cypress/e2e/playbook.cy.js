describe('Sentinel V3 Playbook Workflows', () => {
  beforeEach(() => {
    // Intercept GET requests to backend APIs
    cy.intercept('GET', '/api/sentinel/playbooks*', {
      statusCode: 200,
      body: {
        status: "success",
        total: 2,
        page: 1,
        per_page: 20,
        playbooks: [
          {
            id: 101,
            playbook_id: "pb-101",
            playbook_name: "SSH Brute Force Mitigation",
            technique_id: "T1110.001",
            technique_name: "Password Guessing",
            tactic: "credential-access",
            threat_score: 95,
            status: "pending",
            created_at: "2026-08-03T10:00:00Z",
            updated_at: "2026-08-03T10:00:00Z",
            version: 1,
            is_latest: true,
          },
          {
            id: 102,
            playbook_id: "pb-102",
            playbook_name: "Port Scan Response",
            technique_id: "T1046",
            technique_name: "Network Service Discovery",
            tactic: "discovery",
            threat_score: 75,
            status: "pending",
            created_at: "2026-08-03T10:05:00Z",
            updated_at: "2026-08-03T10:05:00Z",
            version: 1,
            is_latest: true,
          }
        ]
      }
    }).as('getPlaybooks');

    cy.intercept('GET', '/api/sentinel/stats', {
      statusCode: 200,
      body: {
        status: "success",
        total_playbooks: 2,
        pending: 2,
        approved: 0,
        rejected: 0,
        exported: 0,
        approval_rate: 0,
        severity_distribution: { CRITICAL: 1, HIGH: 1 },
        avg_threat_score: 85.0,
        avg_confidence_score: 0.95,
        latest_playbook_at: "2026-08-03T10:05:00Z",
        top_attack_types: [{ attack_type: "Brute Force", count: 1 }],
        generation_trends: [{ date: "2026-08-03", count: 2 }]
      }
    }).as('getStats');

    cy.intercept('GET', '/api/sentinel/mitre/matrix', {
      statusCode: 200,
      body: {
        status: "success",
        matrix: {
          "credential-access": [
            { technique_id: "T1110.001", technique_name: "Password Guessing", count: 1 }
          ],
          "discovery": [
            { technique_id: "T1046", technique_name: "Network Service Discovery", count: 1 }
          ]
        }
      }
    }).as('getMatrix');

    cy.intercept('GET', '/api/sentinel/llm/status', {
      statusCode: 200,
      body: {
        status: "success",
        model: "gemma:2b"
      }
    }).as('getLlmStatus');

    cy.intercept('GET', '/api/sentinel/playbooks/*', (req) => {
      const urlParts = req.url.split('?')[0].split('/');
      const idStr = urlParts[urlParts.length - 1];
      const id = parseInt(idStr, 10);
      
      const playbook = {
        id: id,
        playbook_id: `pb-${id}`,
        playbook_name: id === 101 ? "SSH Brute Force Mitigation" : "Port Scan Response",
        technique_id: id === 101 ? "T1110.001" : "T1046",
        technique_name: id === 101 ? "Password Guessing" : "Network Service Discovery",
        tactic: id === 101 ? "credential-access" : "discovery",
        threat_score: id === 101 ? 95 : 75,
        status: "pending",
        created_at: id === 101 ? "2026-08-03T10:00:00Z" : "2026-08-03T10:05:00Z",
        updated_at: "2026-08-03T10:00:00Z",
        version: 1,
        is_latest: true,
        mitre_url: id === 101 ? "https://attack.mitre.org/techniques/T1110/001/" : "https://attack.mitre.org/techniques/T1046/",
        snort_rule: "alert tcp any any -> any 22 (msg:\"SSH Brute Force\";)",
        sigma_rule: "title: SSH Brute Force\nlogsource:\n  product: linux",
        playbook_content: "# Mitigation steps\n\n1. Block source IP",
        template_name: "template",
        llm_narrative: "AI Summary: Suspicious activity detected."
      };
      
      req.reply({
        statusCode: 200,
        body: {
          status: "success",
          playbook: playbook
        }
      });
    }).as('getPlaybookDetail');

    cy.visit('/sentinel');
    cy.wait('@getPlaybooks');
  });

  it('should display the playbook list', () => {
    cy.get('.playbook-list-container').should('exist');
    cy.get('.playbook-card').should('have.length', 2);
    // Port Scan Response is first since it has a newer created_at date (10:05 vs 10:00)
    cy.get('.playbook-card').first().should('contain', 'Port Scan Response');
    cy.get('.playbook-card').last().should('contain', 'SSH Brute Force Mitigation');
  });

  it('should support individual review and approval workflow', () => {
    // Intercept approve PATCH
    cy.intercept('PATCH', '/api/sentinel/playbooks/*/approve', (req) => {
      const urlParts = req.url.split('/');
      const id = parseInt(urlParts[urlParts.length - 2], 10);
      req.reply({
        statusCode: 200,
        body: {
          status: "success",
          message: "Playbook approved successfully",
          playbook: {
            id: id,
            status: "approved",
            reviewed_by: "e2e_analyst"
          }
        }
      });
    }).as('approvePlaybook');

    // Click on the first card to open details modal (this is Port Scan Response, id 102)
    cy.get('.playbook-card').first().click({ force: true });
    cy.wait('@getPlaybookDetail');
    cy.get('.playbook-viewer-panel').should('exist');

    // Check that standard details are loaded
    cy.get('.pbv-title').should('contain', 'Port Scan Response');

    // Click Approve button to trigger confirmation modal
    cy.get('.btn-approve').should('exist').click({ force: true });

    // Confirm modal should open
    cy.get('.confirm-modal-overlay').should('exist');
    
    // Type analyst name
    cy.get('#analyst-name-input').clear().type('e2e_analyst');
    
    // Click confirm approval button
    cy.get('.btn-confirm-approve').click({ force: true });
    cy.wait('@approvePlaybook');

    // Status should be updated to Approved
    cy.get('.floating-toast.toast-success').should('exist')
      .and('contain', 'Playbook successfully approved');
    cy.get('.approval-status-group .playbook-status-badge').should('contain', 'Approved');
  });

  it('should support multi-select batch approval flow', () => {
    // Intercept batch approve POST
    cy.intercept('POST', '/api/sentinel/playbooks/batch/approve', {
      statusCode: 200,
      body: {
        status: "success",
        results: {
          successful: [101, 102],
          failed: []
        }
      }
    }).as('batchApprove');

    // Make sure card checkboxes exist and check them
    cy.get('.playbook-card-select-checkbox').should('have.length', 2);
    cy.get('.playbook-card-select-checkbox').first().check({ force: true });
    cy.get('.playbook-card-select-checkbox').last().check({ force: true });

    // Floating batch toolbar should appear
    cy.get('.floating-batch-toolbar').should('exist');
    cy.get('.floating-batch-toolbar').should('contain', '2');

    // Click Batch Approve
    cy.get('.btn-batch-approve').click({ force: true });

    // Batch confirmation modal should be visible
    cy.get('.confirm-modal-overlay').should('exist');

    // Type analyst name in batch input
    cy.get('#batch-analyst-name-input').clear().type('batch_analyst');

    // Confirm batch approval
    cy.get('.btn-confirm-approve').click({ force: true });
    cy.wait('@batchApprove');

    // Floating batch toolbar should reset and hide
    cy.get('.floating-batch-toolbar').should('not.exist');
  });

  it('should support downloading PDF and STIX bundles', () => {
    // Intercept export actions
    cy.intercept('POST', '/api/sentinel/playbooks/*/export?format=pdf', {
      statusCode: 200,
      headers: {
        'content-type': 'application/pdf',
        'content-disposition': 'attachment; filename="Export.pdf"'
      },
      body: '%PDF-1.4 mock pdf content'
    }).as('exportPdf');

    cy.intercept('POST', '/api/sentinel/playbooks/*/export?format=stix', {
      statusCode: 200,
      headers: {
        'content-type': 'application/json',
        'content-disposition': 'attachment; filename="Export.stix.json"'
      },
      body: JSON.stringify({ type: "bundle", spec_version: "2.1", objects: [] })
    }).as('exportStix');

    // Click first card to open modal
    cy.get('.playbook-card').first().click({ force: true });
    cy.wait('@getPlaybookDetail');

    // Wait for modal to finish loading details
    cy.get('.pbv-download-bar').should('exist');

    // Click main export/download menu button
    cy.get('#playbook-viewer-export-btn').click({ force: true });
    cy.get('.pbv-export-menu').should('exist');

    // Click PDF download option in dropdown
    cy.get('.pbv-export-item').contains('PDF').click({ force: true });
    cy.wait('@exportPdf');

    // Re-open export menu for STIX
    cy.get('#playbook-viewer-export-btn').click({ force: true });
    cy.get('.pbv-export-item').contains('STIX').click({ force: true });
    cy.wait('@exportStix');

    // Now test download bar buttons (direct client-side generation)
    cy.window().then((win) => {
      cy.stub(win.URL, 'createObjectURL').as('createObjectURL');
      cy.stub(win.HTMLAnchorElement.prototype, 'click').as('anchorClick');
    });

    // Click direct STIX Bundle button in download bar
    cy.get('.pbv-download-btn').contains('STIX Bundle').click({ force: true });
    cy.get('@anchorClick').should('have.been.called');
  });
});
