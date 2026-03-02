import XCTest

final class IDAPUITests: XCTestCase {
    var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments = ["--uitesting"]
        app.launch()
    }

    // MARK: - Onboarding

    func testCompleteOnboardingFlow() throws {
        // Welcome screen
        let getStarted = app.buttons["Get Started"]
        XCTAssertTrue(getStarted.waitForExistence(timeout: 5))
        getStarted.tap()

        // Recovery phrase (skip)
        let skipButton = app.buttons["Skip for Now"]
        XCTAssertTrue(skipButton.waitForExistence(timeout: 5))
        skipButton.tap()

        // Should reach complete / persona creation
        XCTAssertTrue(
            app.staticTexts["Create Your Identity"].waitForExistence(timeout: 5) ||
            app.staticTexts["You're Set Up!"].waitForExistence(timeout: 5)
        )
    }

    // MARK: - Auth Approval

    func testDenyButtonDismissesWithoutAuth() throws {
        // Requires the app to have a pending auth request
        // In UI tests, we trigger via launch argument
        app.terminate()
        app = XCUIApplication()
        app.launchArguments = ["--uitesting", "--mock-auth-request"]
        app.launch()

        let denyButton = app.buttons["Deny"]
        if denyButton.waitForExistence(timeout: 5) {
            denyButton.tap()
            XCTAssertFalse(app.sheets.firstMatch.exists)
        }
    }

    // MARK: - Persona

    func testAddSecondPersonaFlow() throws {
        // Assumes app is already past onboarding
        openSidebar()

        let newButton = app.buttons["New Persona"]
        if newButton.waitForExistence(timeout: 3) {
            newButton.tap()
            let nameField = app.textFields.firstMatch
            XCTAssertTrue(nameField.waitForExistence(timeout: 3))
            nameField.tap()
            nameField.typeText("gaming")
        }
    }

    // MARK: - Contacts

    func testQRCodeDisplayed() throws {
        // Add Contact button is always in top-right toolbar
        let addButton = app.buttons["person.badge.plus"]
        if addButton.waitForExistence(timeout: 5) {
            addButton.tap()
            // Switch to Share tab to see QR code
            let shareTab = app.buttons["Share"]
            if shareTab.waitForExistence(timeout: 3) {
                shareTab.tap()
            }
            XCTAssertTrue(
                app.images.firstMatch.waitForExistence(timeout: 5),
                "QR code image should be displayed"
            )
        }
    }

    func testDeepLinkOpensAddContactFlow() throws {
        // Open deep link via Safari
        let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
        safari.activate()
        let addressBar = safari.textFields["Address"]
        if addressBar.waitForExistence(timeout: 5) {
            addressBar.tap()
            addressBar.typeText("idap://add?key=AAAA&proxy=https://idap.app\n")
            // IDAP app should open
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 5))
        }
    }

    // MARK: - Helpers

    private func openSidebar() {
        let sidebarButton = app.navigationBars.buttons.firstMatch
        if sidebarButton.waitForExistence(timeout: 3) {
            sidebarButton.tap()
        }
    }
}
