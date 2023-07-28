import { MenuProps } from "antd";
import { UserOutlined } from "@ant-design/icons";
import React from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { StyledSubMenu } from "./StyledComponents";

export const SettingsSubNav = () => {
  const { t } = useTranslation();

  const subnav: MenuProps["items"] = [
    {
      key: "general",
      label: (
        <Link to="/settings">{t("settings.general.navigationTitle")}</Link>
      ),
      icon: React.createElement(UserOutlined),
    },
    {
      key: "certificates",
      label: (
        <Link to="/settings/certificates">
          {t("settings.certificates.navigationTitle")}
        </Link>
      ),
      icon: React.createElement(UserOutlined),
    },
  ];

  return (
    <StyledSubMenu
      mode="inline"
      //defaultSelectedKeys={["1"]}
      defaultOpenKeys={["sub"]}
      items={subnav}
    />
  );
};
