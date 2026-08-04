import { test, expect } from '@playwright/test';

test.describe('Sentinel V3 Playbook Workflows', () => {
  test.beforeEach(async ({ page }) => {
    // Mock playbook list request
    await page.route('**/api/sentinel/playbooks*', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
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
        })
      });
    });

    // Mock stats
    await page.route('**/api/sentinel/stats', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
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
        })
      });
    });

    // Mock matrix
    await page.route('**/api/sentinel/mitre/matrix', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: "success",
          matrix: {
            "credential-access": [
              { technique_id: "T1110.001", technique_name: "Password Guessing", count: 1 }
            ],
            "discovery": [
              { technique_id: "T1046", technique_name: "Network Service Discovery", count: 1 }
            ]
          }
        })
      });
    });

    // Mock LLM status
    await page.route('**/api/sentinel/llm/status', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: "success",
          model: "gemma:2b"
        })
      });
    });

    // Mock playbook details request for 101
    await page.route('**/api/sentinel/playbooks/101', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: "success",
          playbook: {
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
            mitre_url: "https://attack.mitre.org/techniques/T1110/001/",
            snort_rule: "alert tcp any any -> any 22 (msg:\"SSH Brute Force\";)",
            sigma_rule: "title: SSH Brute Force\nlogsource:\n  product: linux",
            playbook_content: "# SSH Brute Force Mitigation\n\n1. Block source IP\n2. Notify admin",
            template_name: "ssh_brute_force",
            llm_narrative: "AI Summary: Suspicious SSH brute force activity detected from host."
          }
        })
      });
    });

    // Mock playbook details request for 102
    await page.route('**/api/sentinel/playbooks/102', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: "success",
          playbook: {
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
            mitre_url: "https://attack.mitre.org/techniques/T1046/",
            snort_rule: "alert tcp any any -> any 22 (msg:\"Port Scan\";)",
            sigma_rule: "title: Port Scan\nlogsource:\n  product: linux",
            playbook_content: "# Port Scan Response\n\n1. Inspect ports",
            template_name: "port_scan",
            llm_narrative: "AI Summary: Suspicious port scanning detected."
          }
        })
      });
    });

    await page.goto('http://localhost:5173/sentinel');
  });

  test('should display playbooks list and stats', async ({ page }) => {
    // Wait for the playbook list container to load
    await expect(page.locator('.playbook-list-container')).toBeVisible({ timeout: 10000 });
    
    // Check that we see the two playbooks
    const cards = page.locator('.playbook-card');
    await expect(cards).toHaveCount(2);
    await expect(cards.first()).toContainText('Port Scan Response');
    await expect(cards.last()).toContainText('SSH Brute Force Mitigation');
  });

  test('should support individual playbook review and approval', async ({ page }) => {
    // Mock individual approve PATCH for 102
    await page.route('**/api/sentinel/playbooks/102/approve', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: "success",
          message: "Playbook approved successfully",
          playbook: {
            id: 102,
            status: "approved",
            reviewed_by: "e2e_analyst"
          }
        })
      });
    });

    await expect(page.locator('.playbook-list-container')).toBeVisible();

    // Click on the first card to open details viewer (Port Scan Response, ID 102)
    await page.locator('.playbook-card').first().click();

    // Details modal should open
    const modal = page.locator('.playbook-viewer-panel');
    await expect(modal).toBeVisible();
    await expect(page.locator('.pbv-title')).toContainText('Port Scan Response');

    // Click Approve button in modal footer
    await page.locator('.btn-approve').click();

    // Confirm modal should appear
    const confirmOverlay = page.locator('.confirm-modal-overlay');
    await expect(confirmOverlay).toBeVisible();

    // Input analyst name
    await page.locator('#analyst-name-input').fill('e2e_analyst');

    // Click confirm approve button
    await page.locator('.btn-confirm-approve').click();

    // Success notification toast should appear and status badges update
    await expect(page.locator('.floating-toast.toast-success')).toBeVisible();
    await expect(page.locator('.approval-status-group .playbook-status-badge')).toContainText('Approved');
  });

  test('should support multi-select batch approval UI', async ({ page }) => {
    // Mock batch approve POST
    await page.route('**/api/sentinel/playbooks/batch/approve', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          status: "success",
          results: {
            successful: [101, 102],
            failed: []
          }
        })
      });
    });

    await expect(page.locator('.playbook-list-container')).toBeVisible();

    // Select the playbook checkboxes
    const checkboxes = page.locator('.playbook-card-select-checkbox');
    await expect(checkboxes).toHaveCount(2);

    // Check first and second checkboxes (force since they might have custom overlays)
    await checkboxes.first().check({ force: true });
    await checkboxes.last().check({ force: true });

    // Floating batch toolbar should appear
    const toolbar = page.locator('.floating-batch-toolbar');
    await expect(toolbar).toBeVisible();
    await expect(toolbar).toContainText('2');

    // Click Batch Approve
    await page.locator('.btn-batch-approve').click();

    // Batch confirmation modal opens
    await expect(page.locator('.confirm-modal-overlay')).toBeVisible();

    // Fill in batch analyst name
    await page.locator('#batch-analyst-name-input').fill('batch_analyst');

    // Click confirm batch approve
    await page.locator('.btn-confirm-approve').click();

    // Floating batch toolbar should reset and disappear
    await expect(toolbar).not.toBeVisible();
  });

  test('should support PDF and STIX downloads', async ({ page }) => {
    // Intercept PDF and STIX export responses for 102
    await page.route('**/api/sentinel/playbooks/102/export?format=pdf', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/pdf',
        headers: {
          'Content-Disposition': 'attachment; filename="Port_Scan_Response.pdf"'
        },
        body: Buffer.from('%PDF-1.4 mock pdf data')
      });
    });

    await page.route('**/api/sentinel/playbooks/102/export?format=stix', async route => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        headers: {
          'Content-Disposition': 'attachment; filename="Port_Scan_Response.stix.json"'
        },
        body: JSON.stringify({ type: "bundle", spec_version: "2.1", objects: [] })
      });
    });

    await expect(page.locator('.playbook-list-container')).toBeVisible();

    // Open first playbook details modal (Port Scan Response, ID 102)
    await page.locator('.playbook-card').first().click();
    await expect(page.locator('.playbook-viewer-panel')).toBeVisible();

    // Wait for modal to finish loading details
    await expect(page.locator('.pbv-download-bar')).toBeVisible();

    // Click export dropdown menu
    await page.locator('#playbook-viewer-export-btn').click();
    await expect(page.locator('.pbv-export-menu')).toBeVisible();

    // Click PDF download option
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.locator('.pbv-export-item').filter({ hasText: 'PDF' }).click(),
    ]);
    expect(pdfDownload.suggestedFilename()).toBe('Port_Scan_Response.pdf');

    // Click export dropdown menu again
    await page.locator('#playbook-viewer-export-btn').click();
    const [stixDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.locator('.pbv-export-item').filter({ hasText: 'STIX' }).click(),
    ]);
    expect(stixDownload.suggestedFilename()).toBe('Port_Scan_Response.stix.json');

    // Test client-side direct STIX Bundle download from the download bar
    const [directStixDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.locator('.pbv-download-btn').filter({ hasText: 'STIX Bundle' }).click(),
    ]);
    expect(directStixDownload.suggestedFilename()).toContain('stix.json');
  });
});
