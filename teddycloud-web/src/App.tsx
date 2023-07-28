import React from "react";
import "./App.css";
import { Layout, Menu, MenuProps } from "antd";
import logoImg from "./assets/logo.png";
import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";

import { useTranslation } from "react-i18next";
import { Header } from "antd/es/layout/layout";
import { UiTest } from "./components/UiTest";
import styled from "styled-components";
import { SettingsPage } from "./pages/settings/SettingsPage";
import { CertificatesPage } from "./pages/settings/certificates/CertificatesPage";
import { HomePage } from "./pages/home/HomePage";
import { StatsPage } from "./pages/home/StatsPage";
import { changeLanguage } from "i18next";

const StyledLogo = styled.img`
  height: 32px;
`;
const StyledHeader = styled(Header)`
  color: white;
  display: flex;
  align-items: center;
`;

const StyledLanguageSwitcher = styled.div`
  margin-left: auto;
  display: flex;
  align-items: center;
  > span {
    margin-left: 8px;
    cursor: pointer;
    &:hover {
      text-decoration: underline;
    }
  }
`;

function App() {
  const { t } = useTranslation();

  const mainNav: MenuProps["items"] = [
    { key: "/", label: <Link to="/">{t("home.navigationTitle")}</Link> },
    {
      key: "/settings",
      label: <Link to="/settings">{t("settings.navigationTitle")}</Link>,
    },
  ];
  return (
    <div className="App">
      <Layout>
        <Router>
          <StyledHeader>
            <StyledLogo src={logoImg} /> TeddyCloud Server
            <Menu theme="dark" mode="horizontal" items={mainNav} />
            <StyledLanguageSwitcher>
              <div>{t("language.change")}</div>
              <span onClick={() => changeLanguage("en")}>EN</span>
              <span onClick={() => changeLanguage("de")}>DE</span>
            </StyledLanguageSwitcher>
          </StyledHeader>
          <Layout>
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/home/stats" element={<StatsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route
                path="/settings/certificates"
                element={<CertificatesPage />}
              />
              <Route path="/uitest" element={<UiTest />} />
            </Routes>
          </Layout>
        </Router>
      </Layout>
    </div>
  );
}

export default App;
