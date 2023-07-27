import { Breadcrumb } from "antd";
import { useTranslation } from "react-i18next";
import {
  StyledBreadcrumb,
  StyledContent,
  StyledLayout,
  StyledSider,
} from "../../components/StyledComponents";
import { HomeSubNav } from "../../components/HomeSubNav";

export const StatsPage = () => {
  const { t } = useTranslation();

  return (
    <>
      <StyledSider>
        <HomeSubNav />
      </StyledSider>
      <StyledLayout>
        <StyledBreadcrumb>
          <Breadcrumb.Item>{t("home.navigationTitle")}</Breadcrumb.Item>
          <Breadcrumb.Item>{t("home.stats.navigationTitle")}</Breadcrumb.Item>
        </StyledBreadcrumb>
        <StyledContent>
          <h1>{t(`home.stats.title`)}</h1>
        </StyledContent>
      </StyledLayout>
    </>
  );
};
