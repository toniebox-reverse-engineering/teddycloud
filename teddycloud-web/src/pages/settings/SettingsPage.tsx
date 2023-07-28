import { Breadcrumb } from "antd";
import { useTranslation } from "react-i18next";
import {
  StyledBreadcrumb,
  StyledContent,
  StyledLayout,
  StyledSider,
} from "../../components/StyledComponents";
import { SettingsSubNav } from "../../components/SettingsSubNav";

export const SettingsPage = () => {
  const { t } = useTranslation();

  return (
    <>
      <StyledSider>
        <SettingsSubNav />
      </StyledSider>
      <StyledLayout>
        <StyledBreadcrumb>
          <Breadcrumb.Item>{t("home.navigationTitle")}</Breadcrumb.Item>
          <Breadcrumb.Item>{t("settings.navigationTitle")}</Breadcrumb.Item>
        </StyledBreadcrumb>
        <StyledContent>
          <h1>{t(`settings.title`)}</h1>
        </StyledContent>
      </StyledLayout>
    </>
  );
};
