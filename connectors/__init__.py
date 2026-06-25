from .base import App, Token, Connector, CONNECTOR_TYPES
from .demo_company import DemoCompanyConnector
from .demo_vendor import DemoVendorConnector
from .github import GitHubConnector
from .azure import AzureConnector

CONNECTOR_TYPES.update({
    "demo_company": DemoCompanyConnector,
    "demo_vendor": DemoVendorConnector,
    "github": GitHubConnector,
    "azure": AzureConnector,
})
