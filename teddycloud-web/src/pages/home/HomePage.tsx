import { Breadcrumb } from "antd";
import { useTranslation } from "react-i18next";
import {
  StyledBreadcrumb,
  StyledContent,
  StyledLayout,
  StyledSider,
} from "../../components/StyledComponents";
import { HomeSubNav } from "../../components/HomeSubNav";

export const HomePage = () => {
  const { t } = useTranslation();

  return (
    <>
      <StyledSider>
        <HomeSubNav />
      </StyledSider>
      <StyledLayout>
        <StyledBreadcrumb>
          <Breadcrumb.Item>{t("home.navigationTitle")}</Breadcrumb.Item>
        </StyledBreadcrumb>
        <StyledContent>
          <h1>{t(`home.title`)}</h1>
        </StyledContent>
      </StyledLayout>
    </>
  );
};
